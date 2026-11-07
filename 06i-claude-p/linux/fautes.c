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
 * Il tourne dans notre noyau et sur l'hôte.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
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
    return ecarts != 0 || !assez;
}
