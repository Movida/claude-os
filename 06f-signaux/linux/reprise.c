/*
 * Les appels interrompus par un gestionnaire de signal (6f) : rendent-ils
 * EINTR, ou reprennent-ils (SA_RESTART, restart_syscall) ? Avec poll,
 * ppoll, select, pselect6, epoll, rt_sigsuspend et pause, et le masque qu'ils
 * rendent au retour. Pour chaque appel
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
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
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

/* poll, ppoll, select et pselect6 sur l'eventfd, que l'aide écrit après
 * le signal : repris, ils rendraient 1. Le temps restant de ppoll, select
 * et pselect6 (un délai de 1 s, interrompu au début) est écrit. */
static struct pollfd pfd;
static struct timespec delai_ts;
static struct timeval delai_tv;
static fd_set ensemble;

static long poll_infini(void)
{
    pfd = (struct pollfd){ efd, POLLIN, 0 };
    return syscall(SYS_poll, &pfd, 1, -1);
}

static long poll_1000(void)
{
    pfd = (struct pollfd){ efd, POLLIN, 0 };
    return syscall(SYS_poll, &pfd, 1, 1000);
}

static long ppoll_1s(void)
{
    pfd = (struct pollfd){ efd, POLLIN, 0 };
    delai_ts = (struct timespec){ 1, 0 };
    return syscall(SYS_ppoll, &pfd, 1, &delai_ts, NULL, 8);
}

static long ppoll_infini(void)
{
    pfd = (struct pollfd){ efd, POLLIN, 0 };
    return syscall(SYS_ppoll, &pfd, 1, NULL, NULL, 8);
}

static long select_1s(void)
{
    FD_ZERO(&ensemble);
    FD_SET(efd, &ensemble);
    delai_tv = (struct timeval){ 1, 0 };
    return syscall(SYS_select, efd + 1, &ensemble, NULL, NULL, &delai_tv);
}

static long pselect6_1s(void)
{
    FD_ZERO(&ensemble);
    FD_SET(efd, &ensemble);
    delai_ts = (struct timespec){ 1, 0 };
    return syscall(SYS_pselect6, efd + 1, &ensemble, NULL, NULL, &delai_ts, NULL);
}

/* epoll_wait, epoll_pwait2 sur un epoll qui surveille l'eventfd. */
static long epoll_sur_efd(int quoi)
{
    int ep = epoll_create1(0);
    struct epoll_event e = { .events = EPOLLIN }, evs[4];
    epoll_ctl(ep, EPOLL_CTL_ADD, efd, &e);
    struct timespec une = { 1, 0 };
    long r = quoi == 0 ? syscall(SYS_epoll_wait, ep, evs, 4, -1)
           : quoi == 1 ? syscall(SYS_epoll_wait, ep, evs, 4, 1000)
                       : syscall(SYS_epoll_pwait2, ep, evs, 4, &une, NULL, 8);
    int erreur = errno;
    close(ep);
    errno = erreur;
    return r;
}

static long epoll_infini(void)
{
    return epoll_sur_efd(0);
}

static long epoll_1000(void)
{
    return epoll_sur_efd(1);
}

static long epoll_pwait2_1s(void)
{
    return epoll_sur_efd(2);
}

/* Le reste d'un délai de 1 s, interrompu après quelques millisecondes. */
static int reste_d_une_seconde(long long us)
{
    return us > 500000 && us < 1000000;
}

static long suspendre_vide(void)
{
    uint64_t rien = 0;
    return syscall(SYS_rt_sigsuspend, &rien, 8);
}

static long en_pause(void)
{
    return syscall(SYS_pause);
}

/* Deux signaux pendant un sigsuspend, chacun avec son sa_mask (mesuré sous
 * Linux) : le premier cadre reçoit le masque d'avant sigsuspend, le second
 * le masque courant (celui de sigsuspend, plus ce qu'a ajouté le premier) ;
 * et après, le masque d'avant revient. */
static uint64_t masque_dans_1, masque_dans_2, cadre_de_1, cadre_de_2;

static uint64_t masque_courant(void)
{
    sigset_t m;
    sigprocmask(SIG_BLOCK, NULL, &m);
    uint64_t v;
    memcpy(&v, &m, 8);
    return v;
}

static void note(int sig, siginfo_t *si, void *c)
{
    (void)si;
    ucontext_t *uc = c;
    uint64_t cadre_m;
    memcpy(&cadre_m, &uc->uc_sigmask, 8);
    if (sig == SIGUSR1) {
        masque_dans_1 = masque_courant();
        cadre_de_1 = cadre_m;
    } else {
        masque_dans_2 = masque_courant();
        cadre_de_2 = cadre_m;
    }
}

#define B(s) (1ull << ((s) - 1))

static void deux_signaux_pendant_sigsuspend(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = note;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaction(SIGUSR1, &sa, NULL);
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGQUIT);
    sigaction(SIGUSR2, &sa, NULL);
    sigset_t avant, temporaire;
    sigemptyset(&avant);
    sigaddset(&avant, SIGUSR1);
    sigaddset(&avant, SIGUSR2);
    sigaddset(&avant, SIGINT);
    sigprocmask(SIG_SETMASK, &avant, NULL);
    raise(SIGUSR1);
    raise(SIGUSR2);
    sigemptyset(&temporaire);
    sigaddset(&temporaire, SIGTERM);
    long r = sigsuspend(&temporaire);
    uint64_t apres = masque_courant();
    sigemptyset(&avant);
    sigprocmask(SIG_SETMASK, &avant, NULL);
    uint64_t m_avant = B(SIGUSR1) | B(SIGUSR2) | B(SIGINT), m_1 = B(SIGTERM) | B(SIGHUP) | B(SIGUSR1);
    verifier(r == -1 && errno == EINTR && cadre_de_1 == m_avant && masque_dans_1 == m_1 && cadre_de_2 == m_1
             && masque_dans_2 == (m_1 | B(SIGQUIT) | B(SIGUSR2)) && apres == m_avant,
             "deux signaux pendant sigsuspend : le premier cadre a le masque d'avant, le second le masque courant, puis le masque d'avant");
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
}

/* Le signal qui a réveillé sigsuspend est pris par un autre fil :
 * sigsuspend reprend l'appel, PUIS rend son masque (Linux,
 * `arch_do_signal_or_restart`) ; un signal que ce masque débloque est
 * livré par-dessus l'appel refait, et sigsuspend attend encore. Le fil
 * principal attend dans sigsuspend (SIGUSR2 bloqué le temps de l'attente,
 * rien d'autre) ; l'autre fil lui envoie SIGUSR2, puis SIGUSR1 au
 * processus. Celui-ci réveille le fil principal ; Linux le lui laisse
 * (seul le fil choisi est prévenu, `complete_signal`), notre noyau le
 * donne au premier fil qui retourne vers l'anneau 3 sans le bloquer :
 * l'autre fil, au retour de kill. Alors le fil principal n'a rien à
 * prendre sous son masque d'attente, reçoit SIGUSR2 sous le masque rendu,
 * et attend encore, jusqu'au SIGUSR1 que l'autre fil lui envoie 20 ms
 * plus tard. Vingt fois : chaque fois que l'autre fil a pris SIGUSR1,
 * sigsuspend ne doit finir qu'après le dernier envoi (le nombre de fois
 * est affiché : 0 sur l'hôte, 20 chez nous). */
static volatile int usr1_autre, usr2_vus, fin_envoyee;
static volatile pid_t tid_principal;

static void compte(int sig)
{
    if (sig == SIGUSR2)
        usr2_vus++;
    else if (syscall(SYS_gettid) != tid_principal)
        usr1_autre++;
}

static void *prendre_le_signal(void *rien)
{
    (void)rien;
    dormir_ms(20);
    syscall(SYS_tgkill, getpid(), tid_principal, SIGUSR2);
    kill(getpid(), SIGUSR1);
    dormir_ms(20);
    fin_envoyee = 1;
    syscall(SYS_tgkill, getpid(), tid_principal, SIGUSR1);
    return NULL;
}

static void sigsuspend_refait(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = compte;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    tid_principal = syscall(SYS_gettid);
    int pris_par_l_autre = 0, juste = 1;
    for (int i = 0; i < 20; i++) {
        usr1_autre = usr2_vus = fin_envoyee = 0;
        pthread_t f;
        sigset_t u2;
        sigemptyset(&u2);
        sigaddset(&u2, SIGUSR2);
        pthread_create(&f, NULL, prendre_le_signal, NULL);
        long r = sigsuspend(&u2);
        int fini_apres = fin_envoyee;
        pthread_join(f, NULL);
        /* SIGUSR2 a été livré, ici ou après un EINTR anticipé : il n'est
         * plus en attente. */
        juste &= r == -1 && errno == EINTR && usr2_vus == 1;
        if (usr1_autre) {
            pris_par_l_autre++;
            juste &= fini_apres;
        }
    }
    printf("[linux] reprise : sigsuspend : SIGUSR1 pris par l'autre fil %d fois sur 20\n", pris_par_l_autre);
    verifier(juste, "SIGUSR1 pris par un autre fil : sigsuspend refait, SIGUSR2 livre par-dessus, la fin au signal suivant");
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
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
    deux("poll sans delai", 1, poll_infini, -EINTR, -EINTR);
    deux("poll de 1000 ms", 1, poll_1000, -EINTR, -EINTR);
    deux("ppoll de 1 s", 1, ppoll_1s, -EINTR, -EINTR);
    verifier(reste_d_une_seconde(delai_ts.tv_sec * 1000000LL + delai_ts.tv_nsec / 1000), "ppoll interrompu : le temps restant ecrit");
    deux("ppoll sans delai", 1, ppoll_infini, -EINTR, -EINTR);
    deux("select de 1 s", 1, select_1s, -EINTR, -EINTR);
    verifier(reste_d_une_seconde(delai_tv.tv_sec * 1000000LL + delai_tv.tv_usec), "select interrompu : le temps restant ecrit");
    deux("pselect6 de 1 s", 1, pselect6_1s, -EINTR, -EINTR);
    verifier(reste_d_une_seconde(delai_ts.tv_sec * 1000000LL + delai_ts.tv_nsec / 1000), "pselect6 interrompu : le temps restant ecrit");
    deux("epoll_wait sans delai", 1, epoll_infini, -EINTR, -EINTR);
    deux("epoll_wait de 1000 ms", 1, epoll_1000, -EINTR, -EINTR);
    deux("epoll_pwait2 de 1 s", 1, epoll_pwait2_1s, -EINTR, -EINTR);
    deux("rt_sigsuspend", 0, suspendre_vide, -EINTR, -EINTR);
    deux("pause", 0, en_pause, -EINTR, -EINTR);
    deux_signaux_pendant_sigsuspend();
    sigsuspend_refait();
    verifier(syscall(SYS_restart_syscall) == -1 && errno == EINTR, "restart_syscall sans rien a reprendre : EINTR");
    calcul_sous_signaux();
    printf("[linux] reprise : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
