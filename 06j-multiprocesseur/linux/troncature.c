/*
 * Des fautes de page sur un fichier projeté, pendant qu'un autre fil le
 * raccourcit (6i ; les sondes du relecteur « verrous » de la fin de 6i).
 * Depuis que la mémoire du processus est sous un verrou qui dort, une
 * faute et une troncature la tiennent toutes deux en lecture : elles se
 * croisent. Linux le permet aussi, et garde une règle : une fois ftruncate
 * rendu, aucune page de la projection au-delà de la fin ne se relit, copies
 * privées comprises (truncate_pagecache) ; y toucher fait SIGBUS.
 *
 *     troncature lecture|copie [MS] [DOSSIER]
 *
 * Un fil projette (MAP_PRIVATE) un fichier de 64 pages, puis, après une
 * attente au hasard, les lit (« lecture » : la page du fichier posée par la
 * faute) ou les écrit (« copie » : la copie à l'écriture), l'une après
 * l'autre ; un autre fil, au même moment, ramène le fichier à une page.
 * Puis les pages 1 à 63 sont relues : chacune doit faire SIGBUS. Pendant MS
 * millisecondes (1500 par défaut), dans DOSSIER (/tmp par défaut ; /dev/shm
 * sur l'hôte, un tmpfs comme le nôtre). Il tourne dans notre noyau et sur
 * l'hôte.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096
#define PAGES 64

static int fd;
static long go, fini, arreter;
static __thread sigjmp_buf saut;

static void bus(int s)
{
    (void)s;
    siglongjmp(saut, 1);
}

static long ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Le fil qui raccourcit : à chaque tour que donne `go`, une fois. */
static void *raccourcir(void *arg)
{
    (void)arg;
    long vu = 0;
    for (;;) {
        long g;
        while ((g = __atomic_load_n(&go, __ATOMIC_ACQUIRE)) == vu) {
            if (__atomic_load_n(&arreter, __ATOMIC_ACQUIRE))
                return NULL;
            sched_yield();
        }
        vu = g;
        if (ftruncate(fd, PAGE) != 0) {
            perror("ftruncate");
            exit(2);
        }
        __atomic_store_n(&fini, g, __ATOMIC_RELEASE);
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2 || (strcmp(argv[1], "lecture") != 0 && strcmp(argv[1], "copie") != 0)) {
        printf("[linux] troncature : usage : troncature lecture|copie [MS] [DOSSIER] : ECHEC\n");
        return 2;
    }
    int copie = strcmp(argv[1], "copie") == 0;
    long duree = argc > 2 ? atol(argv[2]) : 1500;
    char chemin[256];
    snprintf(chemin, sizeof chemin, "%s/troncature-XXXXXX", argc > 3 ? argv[3] : "/tmp");
    fd = mkstemp(chemin);
    if (fd < 0) {
        perror("mkstemp");
        return 2;
    }
    unlink(chemin);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = bus;
    sigaction(SIGBUS, &sa, NULL);
    static char x[PAGES * PAGE];
    memset(x, 'X', sizeof x);
    pthread_t b;
    pthread_create(&b, NULL, raccourcir, NULL);
    uint64_t alea = 0x9e3779b97f4a7c15;
    long debut = ms(), tours = 0, touchees = 0, ecarts = 0, fausses = 0, neuves = 0;
    while (ms() - debut < duree) {
        if (ftruncate(fd, PAGES * PAGE) != 0 || pwrite(fd, x, sizeof x, 0) != (ssize_t)sizeof x) {
            perror("remplir");
            return 2;
        }
        volatile unsigned char *z = mmap(NULL, PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (z == MAP_FAILED) {
            perror("mmap");
            return 2;
        }
        /* Pour la copie : les pages d'abord posées en lecture seule. */
        for (int p = 0; copie && p < PAGES; p++)
            if (z[p * PAGE] != 'X')
                fausses++;
        __atomic_store_n(&go, tours + 1, __ATOMIC_RELEASE);
        alea ^= alea << 13;
        alea ^= alea >> 7;
        alea ^= alea << 17;
        for (volatile long i = (long)(alea % 20000); i > 0; i--)
            ;
        volatile int p = 1;
        if (sigsetjmp(saut, 1) == 0)
            for (; p < PAGES; p++, touchees++) {
                if (copie)
                    z[p * PAGE] = 'A';
                else if (z[p * PAGE] != 'X')
                    fausses++;
            }
        while (__atomic_load_n(&fini, __ATOMIC_ACQUIRE) != tours + 1)
            sched_yield();
        /* ftruncate a rendu : les pages 1 à 63 sont au-delà de la fin. */
        for (volatile int q = 1; q < PAGES; q++) {
            if (sigsetjmp(saut, 1) == 0) {
                /* L'octet 1 : 'X' pour la page du fichier ou sa copie, 0 pour
                 * une page neuve posée à sa place. */
                unsigned char v1 = z[q * PAGE + 1];
                if (ecarts++ < 3)
                    printf("[linux] troncature : %s, tour %ld, la page %d se relit apres ftruncate\n", argv[1], tours, (int)q);
                neuves += v1 == 0;
            }
        }
        munmap((void *)z, PAGES * PAGE);
        tours++;
    }
    __atomic_store_n(&arreter, 1, __ATOMIC_RELEASE);
    pthread_join(b, NULL);
    int ok = ecarts == 0 && fausses == 0 && tours > 0;
    if (!ok)
        printf("[linux] troncature : %s : %ld tours, %ld pages touchees, %ld lues fausses, %ld relues apres ftruncate (dont %ld pages neuves)\n",
               argv[1], tours, touchees, fausses, ecarts, neuves);
    printf("[linux] troncature : %s pendant ftruncate, aucune page relue au-dela de la fin : %s\n",
           copie ? "copie a l'ecriture" : "premiere lecture", ok ? "ok" : "ECHEC");
    return !ok;
}
