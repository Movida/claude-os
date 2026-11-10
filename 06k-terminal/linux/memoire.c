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
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

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

/* La dernière page de l'espace d'un programme, que Linux ne donne jamais : sous 47 bits avec quatre
 * niveaux de tables ; sous 56 bits avec cinq (LA57, sur les machines de la CI, où le 0x7ffffffff000
 * de quatre niveaux est une page comme une autre), même si mmap n'y va jamais de lui-même. Demander
 * une page au-delà de 47 bits le dit, sans dépendre du processeur : notre noyau, comme Linux à quatre
 * niveaux, refuse. Écarté : le drapeau la57 de /proc/cpuinfo, qui dit le processeur, pas le noyau. */
static char *derniere_page(void)
{
    void *haut = mmap((void *)(1UL << 47), PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (haut == MAP_FAILED)
        return (char *)0x7ffffffff000;
    munmap(haut, PAGE);
    return (char *)0xfffffffffff000;
}

/* Les refus, avec les codes d'erreur de Linux. */
static void erreurs(void)
{
    int rw = PROT_READ | PROT_WRITE, pa = MAP_PRIVATE | MAP_ANONYMOUS;
    char *derniere = derniere_page();
    verifier(erreur_mmap(NULL, 0, rw, pa, -1, 0) == EINVAL, "mmap de longueur nulle : EINVAL");
    verifier(erreur_mmap(NULL, PAGE, rw, MAP_ANONYMOUS, -1, 0) == EINVAL, "mmap ni prive ni partage : EINVAL");
    verifier(erreur_mmap((void *)0x200000001, PAGE, rw, pa | MAP_FIXED, -1, 0) == EINVAL,
             "MAP_FIXED non aligne : EINVAL");
    verifier(erreur_mmap(NULL, PAGE, rw, pa, -1, 1) == EINVAL, "decalage non aligne : EINVAL");
    verifier(erreur_mmap(NULL, 1UL << 47, rw, pa | MAP_NORESERVE, -1, 0) == ENOMEM, "128 Tio : ENOMEM");
    verifier(erreur_mmap(NULL, PAGE, rw, MAP_PRIVATE, -1, 0) == EBADF, "sans MAP_ANONYMOUS ni fichier : EBADF");
    verifier(erreur_mmap(NULL, PAGE, rw, pa | MAP_FIXED, -1, 0) == EPERM, "MAP_FIXED a l'adresse 0 : EPERM");
    verifier(erreur_mmap(derniere, PAGE, rw, pa | MAP_FIXED, -1, 0) == ENOMEM,
             "MAP_FIXED dans la derniere page : ENOMEM");
    verifier(erreur_de(munmap((void *)0x200000001, PAGE)) == EINVAL, "munmap non aligne : EINVAL");
    verifier(erreur_de(munmap((void *)0x200000000, 0)) == EINVAL, "munmap de longueur nulle : EINVAL");
    verifier(erreur_de(munmap(derniere, PAGE)) == EINVAL, "munmap de la derniere page : EINVAL");
    verifier(munmap((void *)0x500000000, PAGE) == 0, "munmap ou rien n'est projete : 0");
}

/* 64 Gio réservés, une page écrite à chaque bout, puis rendus d'un seul
 * munmap. Le parcours des tables saute ce qui n'est pas projeté : page par
 * page, il ferait seize millions de tours, bien plus que la limite de
 * temps de calcul que pose main (une seconde dans QEMU, et le programme
 * serait arrêté par SIGXCPU). */
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

/* Le noyau peut-il écrire dans cette page ? getrandom y écrit 1 octet :
 * une page en lecture seule, ou sans aucun droit, lui fait rendre EFAULT
 * (sous Linux comme chez nous). C'est la façon de vérifier des droits sans
 * faire de faute dans le programme lui-même. */
static int inscriptible(char *page)
{
    return getrandom(page, 1, 0) == 1;
}

/* mprotect coupe une zone en trois, puis la rend à ses droits : le
 * milieu en lecture seule refuse d'être écrit (EFAULT), les bouts non. */
static void protections(void)
{
    char *p = anonyme(NULL, 3 * PAGE, 0);
    int ok = mprotect(p + PAGE, PAGE, PROT_READ) == 0;
    ok = ok && inscriptible(p) && !inscriptible(p + PAGE) && inscriptible(p + 2 * PAGE);
    ok = ok && mprotect(p + PAGE, PAGE, PROT_READ | PROT_WRITE) == 0 && inscriptible(p + PAGE);
    verifier(ok, "mprotect coupe une zone en trois, puis la rend a ses droits");
    /* Une page de garde, sans aucun droit : ni lue, ni écrite. */
    ok = mprotect(p + 2 * PAGE, PAGE, PROT_NONE) == 0 && !inscriptible(p + 2 * PAGE);
    ok = ok && erreur_de(write(1, p + 2 * PAGE, 1)) == EFAULT;
    verifier(ok, "page de garde (PROT_NONE) : ni lue, ni ecrite");
    munmap(p, 3 * PAGE);
}

/* W+X, comme le compilateur à la volée de JavaScriptCore : du code écrit
 * puis exécuté dans la même page (mov eax, 42 ; ret). */
static void jit(void)
{
    int erreur;
    unsigned char *p = (unsigned char *)projeter(NULL, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
                                                 MAP_PRIVATE | MAP_ANONYMOUS, &erreur);
    int ok = p != MAP_FAILED;
    if (ok) {
        static const unsigned char code[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
        memcpy(p, code, sizeof code);
        int (*fonction)(void) = (int (*)(void))p;
        ok = fonction() == 42;
        munmap(p, PAGE);
    }
    verifier(ok, "mmap W+X : code ecrit puis execute (JIT)");
}

/* Une zone en lecture seule, lue (la page de zéros y est en place), puis
 * rendue inscriptible : la première écriture doit passer par la copie, et
 * la page de zéros rester nulle pour les autres. */
static void ecriture_apres_lecture(void)
{
    int erreur;
    char *p = projeter(NULL, 2 * PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, &erreur);
    int ok = p != MAP_FAILED && p[0] == 0 && p[PAGE] == 0;
    ok = ok && mprotect(p, PAGE, PROT_READ | PROT_WRITE) == 0;
    if (ok) {
        p[0] = 'x';
        ok = p[0] == 'x' && p[PAGE] == 0;
    }
    char *q = projeter(NULL, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, &erreur);
    ok = ok && q != MAP_FAILED && q[0] == 0;
    verifier(ok, "lecture, mprotect en ecriture, ecriture : copie, la page de zeros reste nulle");
    munmap(p, 2 * PAGE);
    munmap(q, PAGE);
}

/* MADV_DONTNEED : les pages se relisent à zéro. Sur une plage avec un
 * trou, le reste est traité, puis ENOMEM. */
static void dontneed(void)
{
    char *p = anonyme(NULL, 3 * PAGE, 0);
    memset(p, 7, 3 * PAGE);
    int ok = madvise(p, PAGE, MADV_DONTNEED) == 0 && p[0] == 0 && p[PAGE] == 7;
    verifier(ok, "MADV_DONTNEED : la page se relit a zero");
    p[0] = 7;
    munmap(p + PAGE, PAGE);
    ok = erreur_de(madvise(p, 3 * PAGE, MADV_DONTNEED)) == ENOMEM && p[0] == 0 && p[2 * PAGE] == 0;
    verifier(ok, "MADV_DONTNEED avec un trou : le reste traite, puis ENOMEM");
    munmap(p, 3 * PAGE);
}

/* Le .bss, au-delà de ce qui vient du fichier : de la mémoire anonyme.
 * MADV_DONTNEED l'y remet à zéro ; MADV_FREE y est permis. Les données
 * initialisées, elles, viennent du fichier : MADV_FREE y est refusé
 * (EINVAL). */
static char bss[4 * PAGE] __attribute__((aligned(4096)));
static char donnees[2 * PAGE] __attribute__((aligned(4096))) = { 1 };

static void programme(void)
{
    bss[PAGE] = 7;
    int ok = madvise(bss, sizeof bss, MADV_DONTNEED) == 0 && bss[PAGE] == 0;
    ok = ok && madvise(bss, sizeof bss, MADV_FREE) == 0;
    verifier(ok, "MADV_DONTNEED sur le .bss : relu a zero");
    ok = erreur_de(madvise(donnees, PAGE, MADV_FREE)) == EINVAL && donnees[0] == 1;
    verifier(ok, "MADV_FREE sur les donnees du programme : EINVAL");
}

/* MADV_POPULATE_WRITE : les pages en place d'avance, à zéro ; refusé
 * (EINVAL) là où l'écriture est interdite. */
static void populate_write(void)
{
    char *p = anonyme(NULL, 8 * PAGE, 0);
    int ok = madvise(p, 8 * PAGE, MADV_POPULATE_WRITE) == 0 && p[0] == 0 && p[7 * PAGE] == 0;
    ok = ok && mprotect(p, PAGE, PROT_READ) == 0 && erreur_de(madvise(p, PAGE, MADV_POPULATE_WRITE)) == EINVAL;
    ok = ok && madvise(p, PAGE, MADV_POPULATE_READ) == 0;
    verifier(ok, "MADV_POPULATE_WRITE et READ ; EINVAL sans le droit d'ecrire");
    munmap(p, 8 * PAGE);
}

/* Les droits de la zone qui contient `a`, lus dans /proc/self/maps (« rw-p »), ou "" si aucune. */
static const char *droits_dans_maps(const void *a, char droits[8])
{
    FILE *f = fopen("/proc/self/maps", "r");
    char ligne[512];
    unsigned long debut, fin;
    droits[0] = 0;
    while (f && fgets(ligne, sizeof ligne, f)) {
        if (sscanf(ligne, "%lx-%lx %7s", &debut, &fin, droits) == 3 && debut <= (uintptr_t)a && (uintptr_t)a < fin)
            break;
        droits[0] = 0;
    }
    if (f)
        fclose(f);
    return droits;
}

/* Une zone déjà promise (VM_ACCOUNT) n'est pas recomptée : deux projections de 1200 Mio côte
 * à côte fusionnent (2400 Mio : plus que les 2 Gio de la machine de nos tests) ; écrites
 * (un octet dans chacune), en lecture seule, puis inscriptibles de nouveau : accepté, comme
 * Linux (`mprotect_fixup`). Sans les écrire, Linux retire VM_ACCOUNT à la zone en lecture
 * seule (elle n'a pas d'`anon_vma`), et la recompte ensuite : refusée sur une machine de
 * 2 Gio ; notre noyau la garde promise (un écart voulu, noyau/src/memoire.rs, `proteger`). */
static void zone_promise(void)
{
    size_t t = (size_t)1200 << 20;
    char *a = mmap(NULL, 2 * t, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    int ok = a != MAP_FAILED
             && mmap(a, t, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == a
             && mmap(a + t, t, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == a + t;
    if (ok) {
        a[0] = 1;
        a[t] = 1;
    }
    ok = ok && mprotect(a, 2 * t, PROT_READ) == 0 && mprotect(a, 2 * t, PROT_READ | PROT_WRITE) == 0;
    verifier(ok, "deux zones promises fusionnees, plus grandes que la memoire : rendues inscriptibles de nouveau, sans recompter");
    if (a != MAP_FAILED)
        munmap(a, 2 * t);
}

/* La taille de la mémoire du programme (/proc/self/statm, en pages). */
static size_t taille_virtuelle(void)
{
    unsigned long pages = 0;
    FILE *f = fopen("/proc/self/statm", "r");
    if (f) {
        if (fscanf(f, "%lu", &pages) != 1)
            pages = 0;
        fclose(f);
    }
    return pages * PAGE;
}

static sigjmp_buf retour_de_faute;

static void sur_faute(int sig)
{
    (void)sig;
    siglongjmp(retour_de_faute, 1);
}

/* Toucher `octets` sous l'adresse courante de la pile, en descendant (une page à la fois,
 * comme une fonction qui réserve un grand tableau) : 1 si une faute a arrêté avant. */
static __attribute__((noinline)) int toucher_la_pile(size_t octets)
{
    /* Une adresse de la pile, par un entier : le compilateur ne la borne pas. */
    volatile char *p = (volatile char *)(uintptr_t)__builtin_frame_address(0);
    if (sigsetjmp(retour_de_faute, 1))
        return 1;
    for (size_t k = PAGE; k <= octets; k += PAGE)
        p[-(long)k] = 1;
    return 0;
}

/* Les limites de ressources de la mémoire, appliquées comme Linux : RLIMIT_AS à mmap
 * (`may_expand_vm`), RLIMIT_DATA à mmap, mprotect et brk (les zones privées inscriptibles
 * hors de la pile, et le tas avec le segment des données), RLIMIT_STACK à la croissance de
 * la pile (`acct_stack_growth` : une faute, SIGSEGV). Chaque limite remise ensuite. */
static void limites(void)
{
    struct rlimit avant, l;
    getrlimit(RLIMIT_AS, &avant);
    l = (struct rlimit){ taille_virtuelle() + (64 << 20), avant.rlim_max };
    setrlimit(RLIMIT_AS, &l);
    char *a = mmap(NULL, 128 << 20, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    char *b = mmap(NULL, 16 << 20, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    verifier(a == MAP_FAILED && errno == ENOMEM && b != MAP_FAILED, "RLIMIT_AS : 128 Mio de plus, ENOMEM ; 16 Mio, accepte");
    /* MAP_FIXED par-dessus ce qui est déjà là : seule la différence compte (la limite
     * rabaissée à 8 Mio de plus : sans le retrait, 16 Mio seraient refusés). */
    l = (struct rlimit){ taille_virtuelle() + (8 << 20), avant.rlim_max };
    setrlimit(RLIMIT_AS, &l);
    char *c = mmap(b, 16 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    verifier(c == b, "RLIMIT_AS : MAP_FIXED sur 16 Mio deja projetes, 8 Mio de marge, accepte");
    munmap(b, 16 << 20);
    setrlimit(RLIMIT_AS, &avant);

    getrlimit(RLIMIT_DATA, &avant);
    l = (struct rlimit){ 32 << 20, avant.rlim_max };
    setrlimit(RLIMIT_DATA, &l);
    a = mmap(NULL, 64 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int e = errno;
    b = mmap(NULL, 64 << 20, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    verifier(a == MAP_FAILED && e == ENOMEM && b != MAP_FAILED, "RLIMIT_DATA : 64 Mio inscriptibles, ENOMEM ; en lecture seule, acceptes");
    verifier(b != MAP_FAILED && erreur_de(mprotect(b, 64 << 20, PROT_READ | PROT_WRITE)) == ENOMEM,
             "RLIMIT_DATA : mprotect qui en fait des donnees, ENOMEM");
    if (b != MAP_FAILED)
        munmap(b, 64 << 20);
    long brk0 = syscall(SYS_brk, 0);
    long brk1 = syscall(SYS_brk, brk0 + (64 << 20));
    verifier(brk1 == brk0, "RLIMIT_DATA : brk de 64 Mio de plus, refuse (la fin ne bouge pas)");
    /* brk compte aussi toutes les données (`may_expand_vm` de do_brk_flags), pas seulement le
     * tas et le segment des données (`check_data_rlimit`) : 24 Mio de mmap inscriptible, puis
     * un brk de 16 Mio, refusé. */
    a = mmap(NULL, 24 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    brk1 = syscall(SYS_brk, brk0 + (16 << 20));
    verifier(a != MAP_FAILED && brk1 == brk0, "RLIMIT_DATA : brk de 16 Mio a cote de 24 Mio de mmap inscriptible, refuse");
    if (a != MAP_FAILED)
        munmap(a, 24 << 20);
    /* MAP_FIXED inscriptible par-dessus 48 Mio en lecture seule : tout ce qui est remplacé
     * compte en moins, données ou non (`pglen - nr_pages`) : accepté. */
    b = mmap(NULL, 48 << 20, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    c = b == MAP_FAILED ? MAP_FAILED : mmap(b, 48 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    verifier(b != MAP_FAILED && c == b, "RLIMIT_DATA : MAP_FIXED inscriptible sur 48 Mio en lecture seule, accepte");
    if (b != MAP_FAILED)
        munmap(b, 48 << 20);
    /* RLIMIT_AS déjà atteinte : `may_expand_vm` refuse les nouveaux droits ET les anciens,
     * et mprotect passe, même au-delà de RLIMIT_DATA. */
    b = mmap(NULL, 64 << 20, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct rlimit espace;
    getrlimit(RLIMIT_AS, &espace);
    l = (struct rlimit){ taille_virtuelle(), espace.rlim_max };
    setrlimit(RLIMIT_AS, &l);
    int p = b == MAP_FAILED ? -1 : mprotect(b, 64 << 20, PROT_READ | PROT_WRITE);
    setrlimit(RLIMIT_AS, &espace);
    verifier(b != MAP_FAILED && p == 0, "RLIMIT_AS atteinte : mprotect qui fait 64 Mio de donnees, accepte");
    if (b != MAP_FAILED)
        munmap(b, 64 << 20);
    /* RLIMIT_DATA à 0 : permis jusqu'à la limite maximale (« Workaround for Valgrind »). */
    l = (struct rlimit){ 0, avant.rlim_max };
    setrlimit(RLIMIT_DATA, &l);
    a = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    verifier(a != MAP_FAILED, "RLIMIT_DATA a 0 : 1 Mio inscriptible, accepte jusqu'a la limite maximale");
    if (a != MAP_FAILED)
        munmap(a, 1 << 20);
    setrlimit(RLIMIT_DATA, &avant);

    /* La pile : une faute au-delà de RLIMIT_STACK, la place pour sa propre faute sur une
     * pile de secours. */
    static char secours[64 << 10];
    stack_t ss = { .ss_sp = secours, .ss_size = sizeof secours };
    sigaltstack(&ss, NULL);
    struct sigaction sa = { .sa_handler = sur_faute, .sa_flags = SA_ONSTACK | SA_NODEFER }, ancienne;
    sigaction(SIGSEGV, &sa, &ancienne);
    getrlimit(RLIMIT_STACK, &avant);
    l = (struct rlimit){ 1 << 20, avant.rlim_max };
    setrlimit(RLIMIT_STACK, &l);
    int arrete = toucher_la_pile(2 << 20);
    setrlimit(RLIMIT_STACK, &avant);
    int passe = !toucher_la_pile(2 << 20);
    sigaction(SIGSEGV, &ancienne, NULL);
    verifier(arrete && passe, "RLIMIT_STACK a 1 Mio : la pile ne grandit pas de 2 Mio (SIGSEGV) ; remise, elle grandit");
}

/* Les refus de mprotect et madvise, et les conseils sans effet. */
static void erreurs_protections(void)
{
    char *p = anonyme(NULL, 2 * PAGE, 0);
    verifier(erreur_de(mprotect(p + 1, PAGE, PROT_READ)) == EINVAL, "mprotect non aligne : EINVAL");
    verifier(mprotect(p, 0, 0x7fff) == 0, "mprotect de longueur nulle : 0, quels que soient les droits");
    verifier(erreur_de(mprotect(p, PAGE, 0x10)) == EINVAL, "mprotect, droit inconnu : EINVAL");
    verifier(erreur_de(mprotect(p, PAGE, PROT_READ | PROT_GROWSDOWN)) == EINVAL,
             "PROT_GROWSDOWN hors de la pile : EINVAL");
    int local;
    char *pile = (char *)((uintptr_t)&local & ~(PAGE - 1));
    verifier(mprotect(pile, PAGE, PROT_READ | PROT_WRITE | PROT_GROWSDOWN) == 0, "PROT_GROWSDOWN sur la pile : accepte");
    verifier(erreur_de(mprotect(p, (size_t)-PAGE, PROT_READ)) == ENOMEM, "mprotect qui deborde : ENOMEM");
    munmap(p + PAGE, PAGE);
    char droits[8];
    verifier(erreur_de(mprotect(p, 2 * PAGE, PROT_READ)) == ENOMEM && strncmp(droits_dans_maps(p, droits), "r--", 3) == 0,
             "mprotect avec un trou : ENOMEM, et la zone d'avant le trou en lecture seule");
    verifier(erreur_de(madvise(p + 1, PAGE, MADV_DONTNEED)) == EINVAL, "madvise non aligne : EINVAL");
    verifier(erreur_de(madvise(p, PAGE, 9999)) == EINVAL, "madvise, conseil inconnu : EINVAL");
    verifier(erreur_de(madvise(p, 0, 9999)) == EINVAL && madvise(p, 0, MADV_DONTNEED) == 0,
             "madvise de longueur nulle : 0, si le conseil existe");
    verifier(erreur_de(madvise(p + PAGE, PAGE, MADV_WILLNEED)) == ENOMEM, "madvise ou rien n'est projete : ENOMEM");
    verifier(erreur_de(madvise(p, (size_t)-PAGE, MADV_DONTNEED)) == EINVAL, "madvise qui deborde : EINVAL");
    int ok = 1;
    static const int sans_effet[] = { MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED, MADV_HUGEPAGE,
                                      MADV_NOHUGEPAGE, MADV_DONTDUMP, MADV_DODUMP, MADV_COLD, MADV_PAGEOUT,
                                      MADV_DONTFORK, MADV_DOFORK, MADV_WIPEONFORK, MADV_KEEPONFORK, MADV_FREE };
    for (size_t i = 0; i < sizeof sans_effet / sizeof *sans_effet; i++)
        ok = ok && madvise(p, PAGE, sans_effet[i]) == 0;
    verifier(ok, "les conseils de madvise que fait claude : acceptes");
    munmap(p, PAGE);
}

static void informations(void)
{
    struct sysinfo s;
    int ok = sysinfo(&s) == 0 && s.mem_unit >= 1 && s.totalram > 0 && s.freeram <= s.totalram;
    verifier(ok, "sysinfo : memoire totale et libre");
}

int main(void)
{
    /* Une seconde de calcul au plus (RLIMIT_CPU, sans limite dure) : c'est
     * ce qui fait mordre le test des 64 Gio. Le noyau ne limite plus le
     * temps d'un programme par défaut, pas plus que Linux. */
    struct rlimit une_seconde = { 1, RLIM_INFINITY };
    verifier(setrlimit(RLIMIT_CPU, &une_seconde) == 0, "une seconde de calcul au plus (RLIMIT_CPU)");
    huit_gio();
    adresses();
    erreurs();
    soixante_quatre_gio();
    coupe();
    populate();
    protections();
    jit();
    ecriture_apres_lecture();
    dontneed();
    programme();
    populate_write();
    erreurs_protections();
    zone_promise();
    limites();
    informations();
    printf("[linux] memoire : %s\n", echecs == 0 ? "toutes les verifications : ok" : "ECHEC");
    return echecs != 0;
}
