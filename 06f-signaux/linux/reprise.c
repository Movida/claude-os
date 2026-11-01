/*
 * Les appels interrompus par un gestionnaire de signal (6f) : rendent-ils
 * EINTR, ou reprennent-ils (SA_RESTART, restart_syscall) ? Pour chaque appel
 * qui attend, un autre fil envoie SIGUSR1 au fil qui attend jusqu'à ce que
 * son gestionnaire ait tourné, puis fait ce qui finit l'attente (écrire
 * l'eventfd, réveiller le futex) : un appel repris rend alors son résultat,
 * un appel interrompu EINTR. Le tableau a été mesuré sous Linux 6.18 ; il
 * tourne sur l'hôte et chez nous, chaque ligne doit dire « ok » des deux
 * côtés. Et deux vérifications que les codes internes de la reprise ne
 * sortent jamais du noyau : restart_syscall appelé par le programme rend
 * EINTR, et un fil qui calcule avec rax = -512 sous une pluie de signaux
 * ne voit ni rax ni RIP changer (le noyau ne doit refaire QUE des appels
 * système, jamais le code interrompu par une interruption).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] reprise : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static volatile int appels;

static void gestionnaire(int sig)
{
    (void)sig;
    appels++;
}

static void poser(int sa_restart)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = gestionnaire;
    sa.sa_flags = sa_restart ? SA_RESTART : 0;
    sigaction(SIGUSR1, &sa, NULL);
}

static void dormir_ms(int ms)
{
    struct timespec t = { 0, ms * 1000000L };
    nanosleep(&t, NULL);
}

/* L'aide : quand le fil `cible` est entré dans l'appel (il le dit juste
 * avant, puis l'aide lui laisse 3 ms pour y dormir : sinon, sur un seul
 * processeur, le signal pourrait tomber avant l'appel), SIGUSR1 toutes les
 * millisecondes jusqu'à ce que le gestionnaire ait tourné, puis, 5 ms plus
 * tard, ce qui finit l'attente. */
static pid_t cible;
static int efd;
static uint32_t mot;
static int fin;
static volatile int dans_l_appel;

static void *aide(void *rien)
{
    (void)rien;
    while (!dans_l_appel)
        sched_yield();
    dormir_ms(3);
    while (!appels) {
        syscall(SYS_tgkill, getpid(), cible, SIGUSR1);
        dormir_ms(1);
    }
    dormir_ms(5);
    uint64_t un = 1;
    if (fin == 1 && write(efd, &un, 8) != 8)
        printf("[linux] reprise : ecriture de l'eventfd : ECHEC\n");
    if (fin == 2) {
        mot = 1;
        syscall(SYS_futex, &mot, FUTEX_WAKE, 1, NULL, NULL, 0);
    }
    return NULL;
}

/* Lance l'aide, fait l'appel, et rend son résultat (ou -errno). */
static long essayer(int sa_restart, int quoi_finit, long (*appel)(void))
{
    poser(sa_restart);
    appels = 0;
    fin = quoi_finit;
    mot = 0;
    efd = eventfd(0, 0);
    cible = (pid_t)syscall(SYS_gettid);
    dans_l_appel = 0;
    pthread_t t;
    pthread_create(&t, NULL, aide, NULL);
    errno = 0;
    dans_l_appel = 1;
    long r = appel();
    if (r < 0)
        r = -errno;
    pthread_join(t, NULL);
    close(efd);
    return r;
}

static long lire_eventfd(void)
{
    uint64_t v;
    return read(efd, &v, 8);
}

static long futex_sans_delai(void)
{
    return syscall(SYS_futex, &mot, FUTEX_WAIT, 0, NULL, NULL, 0);
}

static long futex_delai(void)
{
    struct timespec t = { 5, 0 };
    return syscall(SYS_futex, &mot, FUTEX_WAIT, 0, &t, NULL, 0);
}

static long futex_absolu(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    t.tv_sec += 5;
    return syscall(SYS_futex, &mot, FUTEX_WAIT_BITSET, 0, &t, NULL, FUTEX_BITSET_MATCH_ANY);
}

static struct timespec reste;

static long dormir_relatif(void)
{
    struct timespec t = { 5, 0 };
    reste = (struct timespec){ 99, 0 };
    return syscall(SYS_nanosleep, &t, &reste);
}

static long dormir_clock_relatif(void)
{
    struct timespec t = { 5, 0 };
    reste = (struct timespec){ 99, 0 };
    return syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &t, &reste);
}

static long dormir_clock_absolu(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    t.tv_sec += 5;
    reste = (struct timespec){ 99, 0 };
    return syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, &t, &reste);
}

static long attendre_usr2(void)
{
    uint64_t usr2 = 1ull << (SIGUSR2 - 1);
    return syscall(SYS_rt_sigtimedwait, &usr2, NULL, NULL, 8);
}

/* Les deux colonnes du tableau : avec SA_RESTART, puis sans. */
static void deux(const char *quoi, int quoi_finit, long (*appel)(void), long avec, long sans)
{
    char texte[160];
    long a = essayer(1, quoi_finit, appel);
    long s = essayer(0, quoi_finit, appel);
    snprintf(texte, sizeof texte, "%s : avec SA_RESTART %s, sans %s", quoi, avec == -EINTR ? "EINTR" : "repris",
             sans == -EINTR ? "EINTR" : "repris");
    verifier(a == avec && s == sans, texte);
    if (a != avec || s != sans)
        printf("[linux] reprise : (rendu : %ld et %ld)\n", a, s);
}

/* Le temps restant d'un sommeil de 5 s interrompu au début : écrit, entre
 * 4 et 5 s (Linux peut rendre un peu plus de 5 s : le jeu de sa minuterie,
 * `timer_slack`, mesuré 5,00001). */
static int reste_ecrit(void)
{
    long long ns = reste.tv_sec * 1000000000LL + reste.tv_nsec;
    return ns >= 4000000000LL && ns <= 5001000000LL;
}

/* rax = -512 (ERESTARTSYS) pendant une boucle de calcul, sous des signaux
 * venus d'un autre fil : livrés au retour d'une interruption (l'horloge),
 * jamais d'un appel système ; rien ne doit être refait. */
static volatile int arreter;

static void *pluie(void *rien)
{
    (void)rien;
    for (int i = 0; i < 200 && !arreter; i++) {
        syscall(SYS_tgkill, getpid(), cible, SIGUSR1);
        dormir_ms(1);
    }
    arreter = 1;
    return NULL;
}

static void calcul_sous_signaux(void)
{
    poser(1);
    appels = 0;
    arreter = 0;
    cible = (pid_t)syscall(SYS_gettid);
    pthread_t t;
    pthread_create(&t, NULL, pluie, NULL);
    long rax_vu = -512, tours = 0, mauvais = 0;
    while (!arreter || appels < 10) {
        long r;
        __asm__ volatile("mov $-512, %%rax\n\t"
                         "mov $100000, %%ecx\n"
                         "1:\n\t"
                         "cmp $-512, %%rax\n\t"
                         "jne 2f\n\t"
                         "dec %%ecx\n\t"
                         "jnz 1b\n"
                         "2:"
                         : "=a"(r)
                         :
                         : "rcx", "cc");
        if (r != -512) {
            rax_vu = r;
            mauvais++;
        }
        tours++;
        if (arreter && tours > 100000)
            break;
    }
    arreter = 1;
    pthread_join(t, NULL);
    verifier(mauvais == 0 && rax_vu == -512 && appels >= 10, "un calcul avec rax = -512 sous des signaux : ni rax ni RIP ne changent");
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    deux("read d'un eventfd", 1, lire_eventfd, 8, -EINTR);
    deux("futex WAIT sans delai", 2, futex_sans_delai, 0, -EINTR);
    deux("futex WAIT a delai", 0, futex_delai, -EINTR, -EINTR);
    deux("futex WAIT_BITSET absolu", 0, futex_absolu, -EINTR, -EINTR);
    deux("nanosleep", 0, dormir_relatif, -EINTR, -EINTR);
    verifier(reste_ecrit(), "nanosleep interrompu : le temps restant ecrit");
    deux("clock_nanosleep relatif", 0, dormir_clock_relatif, -EINTR, -EINTR);
    verifier(reste_ecrit(), "clock_nanosleep relatif interrompu : le temps restant ecrit");
    deux("clock_nanosleep absolu", 0, dormir_clock_absolu, -EINTR, -EINTR);
    verifier(reste.tv_sec == 99, "clock_nanosleep absolu interrompu : rien d'ecrit");
    sigset_t u2;
    sigemptyset(&u2);
    sigaddset(&u2, SIGUSR2);
    sigprocmask(SIG_BLOCK, &u2, NULL);
    deux("rt_sigtimedwait", 0, attendre_usr2, -EINTR, -EINTR);
    sigprocmask(SIG_UNBLOCK, &u2, NULL);
    verifier(syscall(SYS_restart_syscall) == -1 && errno == EINTR, "restart_syscall sans rien a reprendre : EINTR");
    calcul_sous_signaux();
    printf("[linux] reprise : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
