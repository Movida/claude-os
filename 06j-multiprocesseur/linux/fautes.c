/*
 * La mémoire d'un processus disputée par ses fils (6i). Depuis 6i, elle est
 * sous un verrou qui dort : en lecture pour les fautes de page, en écriture
 * pour mmap, munmap, mprotect et madvise (le mmap_lock de Linux), et les
 * fautes ne s'attendent plus qu'au moment de poser leurs entrées. Pendant
 * une fraction de seconde :
 *   - quatre fils écrivent, puis relisent, chacun ses pages d'une zone de
 *     4 Mio (des fautes en écriture et en lecture, ensemble) ;
 *   - un fil y rend des pages au hasard (MADV_DONTNEED) : une page rendue se
 *     relit à zéro, jamais autre chose que ce qu'on y avait mis ;
 *   - un fil projette, protège et retire sans cesse d'autres zones (mmap,
 *     mprotect, munmap), et relit leur contenu ;
 *   - le fil principal fait grandir sa pile (une récursion de 2 Mio) : la
 *     faute sous la pile demande la mémoire en écriture, puis la rétrograde.
 * Avec l'argument « fin », un fil appelle exit_group au milieu de tout cela :
 * le processus doit finir, code 0, sans rien laisser (le lanceur le dit) ;
 * un verrou de la mémoire perdu le figerait.
 * Puis « TLB perimee » (6j) : deux fils, chacun épinglé sur son processeur
 * (vérifié par getcpu : sur deux processeurs différents, sinon ECHEC, dès
 * que la machine en a deux) ; A écrit une valeur dans une page, B la lit
 * (les deux TLB gardent la traduction) ; A retire la page, prend un cadre
 * de plus (le « puits » : le cadre que munmap vient de rendre, repris et
 * mis à zéro par la première allocation venue, est ainsi occupé) et en
 * reprojette une à la même adresse (MAP_FIXED) où il écrit une autre
 * valeur ; B doit relire cette valeur-là, jamais l'ancien cadre : le noyau
 * a fait oublier la traduction au processeur de B (le vidage des TLB entre
 * processeurs). Mille fois, les deux fils se passant la main en TOURNANT
 * sur un compteur, sans jamais dormir : un fil qui dort (une barrière de
 * pthread, un futex) cède son processeur, qui charge l'espace du noyau, et
 * recharger CR3 vide son TLB ; B ne pouvait alors plus relire une
 * traduction périmée. Sans le puits, B relisait 0 même sans vidage : le
 * cadre rendu était déjà repris et mis à zéro (la relecture de 6j, et deux
 * essais en coupant le vidage à distance dans le noyau ; le troisième dit
 * ECHEC dès le premier tour).
 * Il tourne dans notre noyau et sur l'hôte.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096
#define ZONE (4 << 20)
#define TOUCHEURS 4
#define DUREE_MS 300

static unsigned char *zone;
static volatile int arreter;
static int ecarts;
static char ecart[256];
static long tours[TOUCHEURS + 2];

/* Un résultat que Linux ne permet pas : le premier est gardé, pour le dire. */
static void ecart_vu(const char *quoi, unsigned long valeur)
{
    if (__atomic_fetch_add(&ecarts, 1, __ATOMIC_RELAXED) == 0)
        snprintf(ecart, sizeof ecart, "%s (%#lx)", quoi, valeur);
}

static long maintenant_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Un générateur pseudo-aléatoire à soi (xorshift) : rand() prend un verrou
 * de la glibc, qui sérialiserait les fils. */
static uint64_t suivant(uint64_t *etat)
{
    uint64_t x = *etat;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *etat = x;
}

/* Écrit dans chacune de ses pages une valeur qui dit qui et quand, puis la
 * relit : elle doit y être, ou zéro si le rendeur est passé entre-temps. */
static void *toucheur(void *arg)
{
    long moi = (long)arg;
    unsigned char *debut = zone + moi * (ZONE / TOUCHEURS);
    for (long tour = 1; !arreter; tour++) {
        for (long p = 0; p < ZONE / TOUCHEURS; p += PAGE) {
            volatile uint64_t *mot = (volatile uint64_t *)(debut + p);
            uint64_t valeur = (uint64_t)moi << 56 | (uint64_t)tour << 20 | (uint64_t)p >> 12;
            *mot = valeur;
            uint64_t lu = *mot;
            if (lu != valeur && lu != 0)
                ecart_vu("une page relit autre chose que sa valeur ou zero", lu);
        }
        tours[moi]++;
    }
    return NULL;
}

/* Rend des pages de la zone au hasard. */
static void *rendeur(void *arg)
{
    (void)arg;
    uint64_t etat = 0x9e3779b97f4a7c15;
    while (!arreter) {
        long p = (long)(suivant(&etat) % (ZONE / PAGE)) * PAGE;
        if (madvise(zone + p, PAGE * 4 <= ZONE - p ? PAGE * 4 : PAGE, MADV_DONTNEED) != 0)
            ecart_vu("madvise", errno);
        tours[TOUCHEURS]++;
    }
    return NULL;
}

/* Projette, protège, relit et retire d'autres zones, sans cesse. */
static void *cartographe(void *arg)
{
    (void)arg;
    while (!arreter) {
        unsigned char *z = mmap(NULL, 16 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (z == MAP_FAILED) {
            ecart_vu("mmap", errno);
            continue;
        }
        for (int i = 0; i < 16; i++)
            z[i * PAGE] = (unsigned char)(i + 1);
        if (mprotect(z, 16 * PAGE, PROT_READ) != 0)
            ecart_vu("mprotect", errno);
        for (int i = 0; i < 16; i++)
            if (z[i * PAGE] != (unsigned char)(i + 1))
                ecart_vu("une zone protegee relit autre chose", z[i * PAGE]);
        if (munmap(z, 16 * PAGE) != 0)
            ecart_vu("munmap", errno);
        tours[TOUCHEURS + 1]++;
    }
    return NULL;
}

/* Une récursion qui fait grandir la pile du fil principal : 512 cadres de
 * 4 Kio, chacun écrit (la faute sous la pile l'étend). */
static unsigned long descendre(int profondeur)
{
    volatile unsigned char cadre[PAGE];
    cadre[0] = (unsigned char)profondeur;
    cadre[PAGE - 1] = (unsigned char)(profondeur >> 8);
    if (profondeur == 0)
        return cadre[0];
    return cadre[0] + cadre[PAGE - 1] + descendre(profondeur - 1);
}

/* Avec « fin » : exit_group au milieu des fautes, des madvise et des munmap
 * des autres fils. */
/* Le test « TLB périmée » : la page, la barrière des deux fils, et ce que
 * B a vu. */
static volatile unsigned char *page_tlb;
/* Le puits : une page neuve par tour, touchée par A juste après son munmap
 * (voir l'en-tête). */
static volatile unsigned char *puits_tlb;
/* Le pas des deux fils, dans une AUTRE page que page_tlb : quatre par tour,
 * A franchit les impairs, B les pairs. */
static int pas_tlb;
static int tlb_perimee, tlb_cpu_a = -1, tlb_cpu_b = -1;
#define TOURS_TLB 1000

static void attendre_pas(int n)
{
    while (__atomic_load_n(&pas_tlb, __ATOMIC_ACQUIRE) < n)
        __builtin_ia32_pause();
}

static void franchir_pas(int n)
{
    __atomic_store_n(&pas_tlb, n, __ATOMIC_RELEASE);
}

static int epingler(int cpu)
{
    cpu_set_t c;
    CPU_ZERO(&c);
    CPU_SET(cpu, &c);
    if (pthread_setaffinity_np(pthread_self(), sizeof c, &c) != 0)
        return -1;
    sched_yield();
    return sched_getcpu();
}

static void *tlb_a(void *arg)
{
    tlb_cpu_a = epingler((int)(long)arg);
    for (int tour = 0; tour < TOURS_TLB; tour++) {
        int p = tour * 4;
        page_tlb[0] = 0x42;
        franchir_pas(p + 1); /* B lit 0x42 */
        attendre_pas(p + 2); /* B a lu */
        munmap((void *)page_tlb, PAGE);
        puits_tlb[tour * PAGE] = 0x99;
        if (mmap((void *)page_tlb, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
            ecart_vu("TLB : mmap MAP_FIXED", tour);
        page_tlb[0] = 0x24;
        franchir_pas(p + 3); /* B relit : 0x24 */
        attendre_pas(p + 4); /* B a relu */
    }
    return NULL;
}

static void *tlb_b(void *arg)
{
    tlb_cpu_b = epingler((int)(long)arg);
    for (int tour = 0; tour < TOURS_TLB; tour++) {
        int p = tour * 4;
        attendre_pas(p + 1);
        if (page_tlb[0] != 0x42)
            ecart_vu("TLB : B ne lit pas ce qu'A a ecrit", page_tlb[0]);
        franchir_pas(p + 2);
        attendre_pas(p + 3);
        unsigned char v = page_tlb[0];
        if (v != 0x24) {
            tlb_perimee++;
            if (tlb_perimee == 1)
                ecart_vu("TLB perimee : B ne relit pas la page neuve", v);
        }
        franchir_pas(p + 4);
    }
    return NULL;
}

/* Deux processeurs permis, s'il y en a : les deux premiers du masque. */
static int deux_processeurs(int *a, int *b)
{
    cpu_set_t c;
    if (sched_getaffinity(0, sizeof c, &c) != 0)
        return 0;
    *a = *b = -1;
    for (int i = 0; i < CPU_SETSIZE; i++)
        if (CPU_ISSET(i, &c)) {
            if (*a < 0)
                *a = i;
            else if (*b < 0) {
                *b = i;
                return 1;
            }
        }
    return 0;
}

static void tester_tlb(void)
{
    int a, b;
    if (!deux_processeurs(&a, &b)) {
        printf("[linux] fautes : TLB perimee : un seul processeur, rien a verifier\n");
        return;
    }
    page_tlb = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    puits_tlb = mmap(NULL, TOURS_TLB * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page_tlb == MAP_FAILED || puits_tlb == MAP_FAILED) {
        ecart_vu("TLB : mmap", 0);
        return;
    }
    pthread_t fa, fb;
    pthread_create(&fa, NULL, tlb_a, (void *)(long)a);
    pthread_create(&fb, NULL, tlb_b, (void *)(long)b);
    pthread_join(fa, NULL);
    pthread_join(fb, NULL);
    munmap((void *)page_tlb, PAGE);
    munmap((void *)puits_tlb, TOURS_TLB * PAGE);
    if (tlb_cpu_a != a || tlb_cpu_b != b)
        ecart_vu("TLB : les deux fils ne sont pas chacun sur son processeur", (unsigned long)(tlb_cpu_a * 64 + tlb_cpu_b));
    if (tlb_perimee == 0 && tlb_cpu_a == a && tlb_cpu_b == b)
        printf("[linux] fautes : TLB perimee : %d fois une page retiree et reprojetee par un fil, relue par l'autre sur son processeur, jamais l'ancien cadre : ok\n", TOURS_TLB);
    else
        printf("[linux] fautes : TLB perimee : %d relectures de l'ancienne page sur %d, fils sur les processeurs %d et %d (attendus %d et %d) : ECHEC\n",
               tlb_perimee, TOURS_TLB, tlb_cpu_a, tlb_cpu_b, a, b);
}

static void *finisseur(void *arg)
{
    (void)arg;
    struct timespec t = {0, 50 * 1000000};
    nanosleep(&t, NULL);
    syscall(SYS_exit_group, 0);
    return NULL;
}

int main(int argc, char **argv)
{
    int fin = argc > 1 && strcmp(argv[1], "fin") == 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    zone = mmap(NULL, ZONE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (zone == MAP_FAILED) {
        printf("[linux] fautes : mmap de la zone : ECHEC\n");
        return 1;
    }
    pthread_t fils[TOUCHEURS + 3];
    int n = 0;
    for (long i = 0; i < TOUCHEURS; i++)
        pthread_create(&fils[n++], NULL, toucheur, (void *)i);
    pthread_create(&fils[n++], NULL, rendeur, NULL);
    pthread_create(&fils[n++], NULL, cartographe, NULL);
    if (fin) {
        printf("[linux] fautes : exit_group au milieu des fautes, des madvise et des munmap des autres fils\n");
        pthread_create(&fils[n++], NULL, finisseur, NULL);
    }
    long debut = maintenant_ms(), recursions = 0;
    unsigned long somme = 0;
    while (maintenant_ms() - debut < DUREE_MS || fin) {
        somme += descendre(512);
        recursions++;
    }
    arreter = 1;
    for (int i = 0; i < n; i++)
        pthread_join(fils[i], NULL);
    /* La somme d'une descente : 0 pour le dernier cadre, puis (p mod 256)
     * + (p / 256) pour chacun des autres, relus dans leurs pages. */
    unsigned long attendue = 0;
    for (int p = 1; p <= 512; p++)
        attendue += (unsigned long)(p & 0xff) + (unsigned long)((p >> 8) & 0xff);
    if (somme != attendue * (unsigned long)recursions)
        ecart_vu("la pile relit autre chose", somme);
    int assez = recursions > 0 && tours[TOUCHEURS] > 0 && tours[TOUCHEURS + 1] > 0;
    for (int i = 0; i < TOUCHEURS; i++)
        assez &= tours[i] > 0;
    if (ecarts == 0 && assez)
        printf("[linux] fautes : quatre fils fautent pendant madvise, mmap, mprotect et munmap, la pile grandit : ok\n");
    else
        printf("[linux] fautes : %d ecarts, le premier : %s ; chacun a tourne : %s : ECHEC\n",
               ecarts, ecarts ? ecart : "aucun", assez ? "oui" : "non");
    int avant = ecarts;
    tester_tlb();
    return ecarts != 0 || !assez || avant != ecarts;
}
