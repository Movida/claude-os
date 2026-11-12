/*
 * Les minuteurs (les soldes d'avant 6k) : timerfd, un minuteur derrière un
 * descripteur, qu'attend une boucle d'événements bâtie sur epoll ; les
 * alarmes d'un processus (setitimer, getitimer, alarm) ; les minuteurs
 * POSIX (timer_create et les siens), sur les horloges du temps et du
 * calcul. Il
 * tourne dans notre noyau et sur l'hôte (make tests-hote) : chaque ligne
 * doit dire « ok » des deux côtés, d'après ce qu'a mesuré Linux 6.18.
 *
 * Les comptes d'échéances d'un minuteur périodique ne se vérifient pas à
 * l'unité près (une machine chargée lit plus tard) : ils sont bornés par
 * l'heure lue avant et après, ce qui reste exact sous toute charge.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#ifndef TFD_IOC_SET_TICKS
#define TFD_IOC_SET_TICKS _IOW('T', 0, uint64_t)
#endif

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] minuteurs : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* Le numéro d'erreur d'un appel (0 s'il a réussi). */
static int erreur(long r)
{
    return r < 0 ? errno : 0;
}

static int64_t ns(clockid_t horloge)
{
    struct timespec t;
    clock_gettime(horloge, &t);
    return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static struct itimerspec en(int64_t intervalle, int64_t valeur)
{
    struct itimerspec s = {
        { intervalle / 1000000000, intervalle % 1000000000 },
        { valeur / 1000000000, valeur % 1000000000 },
    };
    return s;
}

static int64_t en_ns(struct timespec t)
{
    return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static void creation(void)
{
    verifier(erreur(timerfd_create(CLOCK_MONOTONIC, 4)) == EINVAL, "timerfd_create, drapeau inconnu : EINVAL");
    verifier(erreur(timerfd_create(CLOCK_PROCESS_CPUTIME_ID, 0)) == EINVAL, "horloge de calcul : EINVAL");
    verifier(erreur(timerfd_create(CLOCK_MONOTONIC_RAW, 0)) == EINVAL, "CLOCK_MONOTONIC_RAW : EINVAL");
    verifier(erreur(timerfd_create(CLOCK_REALTIME_ALARM, 0)) == EPERM, "horloge d'alarme, sans CAP_WAKE_ALARM : EPERM");

    int t = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    verifier(t >= 0 && fcntl(t, F_GETFL) == (O_RDWR | O_NONBLOCK), "F_GETFL : O_RDWR | O_NONBLOCK");
    verifier(fcntl(t, F_GETFD) == FD_CLOEXEC, "TFD_CLOEXEC : FD_CLOEXEC");
    char chemin[64], lien[64] = { 0 };
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", t);
    verifier(readlink(chemin, lien, sizeof lien - 1) > 0 && strcmp(lien, "anon_inode:[timerfd]") == 0,
             "/proc/self/fd : anon_inode:[timerfd]");

    uint64_t v;
    struct itimerspec s;
    verifier(timerfd_gettime(t, &s) == 0 && en_ns(s.it_value) == 0 && en_ns(s.it_interval) == 0,
             "timerfd_gettime d'un minuteur neuf : tout a zero");
    verifier(erreur(read(t, &v, 8)) == EAGAIN, "read d'un minuteur desarme, non bloquant : EAGAIN");
    verifier(erreur(read(t, &v, 4)) == EINVAL, "read de 4 octets : EINVAL");
    verifier(erreur(write(t, &v, 8)) == EINVAL, "write : EINVAL");
    verifier(lseek(t, 10, SEEK_SET) == 0, "lseek : rien ne bouge (0)");
    verifier(erreur(pread(t, &v, 8, 0)) == ESPIPE, "pread : ESPIPE");
    verifier(erreur(ioctl(t, FIONREAD, &v)) == ENOTTY, "ioctl inconnu : ENOTTY");

    s = en(0, 1000000000);
    verifier(erreur(timerfd_settime(t, 4, &s, NULL)) == EINVAL, "timerfd_settime, drapeau inconnu : EINVAL");
    s.it_value.tv_nsec = 1000000000;
    verifier(erreur(timerfd_settime(t, 0, &s, NULL)) == EINVAL, "nanosecondes a 10^9 : EINVAL");
    s = en(0, 1000000000);
    s.it_interval.tv_sec = -1;
    verifier(erreur(timerfd_settime(t, 0, &s, NULL)) == EINVAL, "periode negative : EINVAL");
    verifier(erreur(syscall(SYS_timerfd_settime, t, 0, (void *)8, NULL)) == EFAULT, "valeur illisible : EFAULT");
    /* La valeur lue, puis vérifiée, AVANT le descripteur. */
    verifier(erreur(syscall(SYS_timerfd_settime, 999, 0, (void *)8, NULL)) == EFAULT,
             "valeur illisible et descripteur ferme : EFAULT d'abord");
    s.it_interval.tv_sec = 0;
    verifier(erreur(timerfd_settime(999, 0, &s, NULL)) == EBADF, "descripteur ferme : EBADF");
    int e = eventfd(0, 0);
    verifier(erreur(timerfd_settime(e, 0, &s, NULL)) == EINVAL && erreur(timerfd_gettime(e, &s)) == EINVAL,
             "un eventfd n'est pas un timerfd : EINVAL");
    close(e);
    int p = open("/", O_PATH);
    verifier(erreur(timerfd_gettime(p, &s)) == EBADF, "un descripteur O_PATH : EBADF");
    close(p);
    verifier(erreur(timerfd_gettime(t, (void *)8)) == EFAULT, "timerfd_gettime vers une adresse invalide : EFAULT");

    /* L'ancienne valeur s'écrit APRÈS l'armement : armé quand même. */
    s = en(0, 10000000000LL);
    verifier(erreur(timerfd_settime(t, 0, &s, (void *)8)) == EFAULT, "ancienne valeur vers une adresse invalide : EFAULT");
    verifier(timerfd_gettime(t, &s) == 0 && en_ns(s.it_value) > 9000000000LL, "... mais le minuteur est arme");
    struct itimerspec ancienne;
    s = en(0, 0);
    verifier(timerfd_settime(t, 0, &s, &ancienne) == 0 && en_ns(ancienne.it_value) > 9000000000LL
             && en_ns(ancienne.it_value) <= 10000000000LL && en_ns(ancienne.it_interval) == 0,
             "desarme : l'ancienne valeur, entre 9 et 10 s");
    verifier(timerfd_gettime(t, &s) == 0 && en_ns(s.it_value) == 0, "desarme : plus rien ne reste");

    /* Une valeur au-delà de 292 ans est ramenée à KTIME_MAX (un s64 en
     * nanosecondes), l'échéance aussi : il reste moins de 9223372037 s. */
    s.it_interval.tv_sec = s.it_interval.tv_nsec = s.it_value.tv_nsec = 0;
    s.it_value.tv_sec = INT64_MAX;
    verifier(timerfd_settime(t, 0, &s, NULL) == 0 && timerfd_gettime(t, &s) == 0
             && s.it_value.tv_sec <= 9223372036LL && s.it_value.tv_sec > 9223372036LL - 100000000,
             "arme pour plus de 292 ans : ramene a KTIME_MAX");
    s = en(0, 0);
    timerfd_settime(t, 0, &s, NULL);

    v = 0;
    verifier(erreur(ioctl(t, TFD_IOC_SET_TICKS, &v)) == EINVAL, "TFD_IOC_SET_TICKS a 0 : EINVAL");
    verifier(erreur(ioctl(t, TFD_IOC_SET_TICKS, (void *)8)) == EFAULT, "TFD_IOC_SET_TICKS illisible : EFAULT");
    v = 5;
    uint64_t lu = 0;
    verifier(ioctl(t, TFD_IOC_SET_TICKS, &v) == 0 && read(t, &lu, 8) == 8 && lu == 5,
             "TFD_IOC_SET_TICKS a 5 : read rend 5");
    close(t);
}

static void une_fois(void)
{
    int t = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec s = en(0, 20000000);
    int64_t avant = ns(CLOCK_MONOTONIC);
    verifier(timerfd_settime(t, 0, &s, NULL) == 0, "une echeance dans 20 ms");
    uint64_t v = 0;
    /* Une lecture bloquante : elle attend l'échéance. */
    verifier(read(t, &v, 8) == 8 && v == 1 && ns(CLOCK_MONOTONIC) - avant >= 20000000,
             "read bloquant : 1 echeance, au bout de 20 ms au moins");
    verifier(timerfd_gettime(t, &s) == 0 && en_ns(s.it_value) == 0 && en_ns(s.it_interval) == 0,
             "echu une fois : plus rien ne reste");

    /* readv : les 8 octets à la suite, sur deux morceaux de 4. */
    s = en(0, 1000000);
    timerfd_settime(t, 0, &s, NULL);
    uint32_t moities[2] = { 0, 7 };
    struct iovec morceaux[2] = { { &moities[0], 4 }, { &moities[1], 4 } };
    verifier(readv(t, morceaux, 2) == 8 && moities[0] == 1 && moities[1] == 0, "readv sur deux morceaux de 4 : 8 octets");
    close(t);
}

static void periodique(void)
{
    int t = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    const int64_t periode = 10000000;
    struct itimerspec s = en(periode, periode);
    int64_t t0 = ns(CLOCK_MONOTONIC);
    timerfd_settime(t, 0, &s, NULL);
    int64_t t1 = ns(CLOCK_MONOTONIC);
    struct timespec dodo = { 0, 55000000 };
    nanosleep(&dodo, NULL);
    int64_t t2 = ns(CLOCK_MONOTONIC);
    uint64_t v = 0;
    ssize_t n = read(t, &v, 8);
    int64_t t3 = ns(CLOCK_MONOTONIC);
    /* Les échéances tombent à t + k × 10 ms (k ≥ 1), t entre t0 et t1, la
     * lecture entre t2 et t3. */
    uint64_t moins = (uint64_t)((t2 - t1) / periode), plus = (uint64_t)((t3 - t0) / periode);
    verifier(n == 8 && v >= moins && v <= plus, "periodique de 10 ms, lu apres 55 ms : le compte des periodes passees");
    verifier(timerfd_gettime(t, &s) == 0 && en_ns(s.it_interval) == periode && en_ns(s.it_value) > 0
             && en_ns(s.it_value) <= periode, "timerfd_gettime : la periode, et moins d'une periode restante");

    /* Une échéance absolue (REALTIME) passée de 9 s, toutes les 2 s : -9,
     * -7, -5, -3, -1 : cinq échéances d'un coup, la suivante dans 1 s. */
    int r = timerfd_create(CLOCK_REALTIME, 0);
    int64_t maintenant = ns(CLOCK_REALTIME);
    s = en(2000000000LL, maintenant - 9000000000LL);
    struct pollfd pf = { r, POLLIN, 0 };
    verifier(timerfd_settime(r, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &s, NULL) == 0
             && poll(&pf, 1, 1000) == 1 && pf.revents == POLLIN, "REALTIME absolu dans le passe : POLLIN aussitot");
    verifier(read(r, &v, 8) == 8 && v == 5, "toutes les 2 s depuis -9 s : 5 echeances d'un coup");
    verifier(timerfd_gettime(r, &s) == 0 && en_ns(s.it_value) > 0 && en_ns(s.it_value) <= 1000000000,
             "la suivante dans moins d'une seconde");
    /* Une échéance d'avant le démarrage : 1 s après 1970, toutes les
     * secondes. Les périodes se comptent depuis elle (Linux la garde dans
     * la base REALTIME) : autant d'échéances que de secondes depuis 1970,
     * et la suivante tombe à la seconde ronde de la date. */
    s = en(1000000000LL, 1000000000LL);
    timerfd_settime(r, TFD_TIMER_ABSTIME, &s, NULL);
    struct timespec reel;
    verifier(read(r, &v, 8) == 8 && timerfd_gettime(r, &s) == 0 && clock_gettime(CLOCK_REALTIME, &reel) == 0
             && v + 2 >= (uint64_t)reel.tv_sec && v <= (uint64_t)reel.tv_sec, "REALTIME absolu a 1 s apres 1970 : une echeance par seconde depuis");
    int64_t ecart = (en_ns(s.it_value) - (1000000000 - reel.tv_nsec) % 1000000000 + 1000000000) % 1000000000;
    verifier(s.it_value.tv_sec == 0 && (ecart < 20000000 || ecart > 980000000), "et la suivante a la seconde ronde de la date");

    /* settime sur un périodique échu : l'ancienne valeur, avancée. */
    s = en(periode, periode);
    timerfd_settime(t, 0, &s, NULL);
    nanosleep(&dodo, NULL);
    struct itimerspec ancienne;
    s = en(0, 0);
    verifier(timerfd_settime(t, 0, &s, &ancienne) == 0 && en_ns(ancienne.it_interval) == periode
             && en_ns(ancienne.it_value) > 0 && en_ns(ancienne.it_value) <= periode,
             "settime d'un periodique echu : l'ancienne valeur, avancee a l'echeance suivante");
    verifier(erreur(read(t, &v, 8)) == EAGAIN, "et le compte remis a zero : EAGAIN");
    close(r);
    close(t);
}

/* Les bornes : une échéance au-delà de KTIME_MAX (292 ans, en ns) y est
 * ramenée (`ktime_add_safe`), dans la base où Linux range le minuteur à
 * son armement : celle de son horloge, sauf un REALTIME relatif, rangé
 * dans MONOTONIC (mesuré : ce qui reste est KTIME_MAX moins le temps
 * monotone, et moins la date pour un REALTIME absolu). Un périodique de
 * période énorme de même, après sa première échéance. Et une lecture qui
 * faute à mi-copie rend ce qu'elle a copié (`copy_to_iter`). */
static void bornes(void)
{
    const int64_t ktime_max_s = INT64_MAX / 1000000000;
    struct { clockid_t horloge; int absolue; int periodique; clockid_t base; const char *nom; } cas[] = {
        { CLOCK_MONOTONIC, 0, 0, CLOCK_MONOTONIC, "MONOTONIC relatif" },
        { CLOCK_REALTIME, 0, 0, CLOCK_MONOTONIC, "REALTIME relatif (base MONOTONIC)" },
        { CLOCK_REALTIME, 1, 0, CLOCK_REALTIME, "REALTIME absolu" },
        { CLOCK_MONOTONIC, 0, 1, CLOCK_MONOTONIC, "MONOTONIC periodique" },
        { CLOCK_REALTIME, 0, 1, CLOCK_MONOTONIC, "REALTIME periodique relatif" },
        { CLOCK_REALTIME, 1, 1, CLOCK_REALTIME, "REALTIME periodique absolu" },
    };
    for (unsigned k = 0; k < sizeof cas / sizeof cas[0]; k++) {
        char quoi[160];
        int t = timerfd_create(cas[k].horloge, TFD_NONBLOCK);
        /* LONG_MAX s ; périodique, une première échéance tout de suite. */
        struct itimerspec s = { { 0, 0 }, { INT64_MAX, 0 } }, g;
        if (cas[k].periodique) {
            s.it_interval.tv_sec = INT64_MAX;
            s.it_value.tv_sec = cas[k].absolue ? ns(CLOCK_REALTIME) / 1000000000 : 0;
            s.it_value.tv_nsec = 1;
        }
        timerfd_settime(t, cas[k].absolue ? TFD_TIMER_ABSTIME : 0, &s, NULL);
        uint64_t c = 1;
        if (cas[k].periodique) {
            struct pollfd pf = { t, POLLIN, 0 };
            poll(&pf, 1, 1000);
            c = 0;
            if (read(t, &c, 8) != 8)
                c = 0;
        }
        timerfd_gettime(t, &g);
        int64_t attendu = ktime_max_s - ns(cas[k].base) / 1000000000;
        snprintf(quoi, sizeof quoi, "%s de LONG_MAX s : KTIME_MAX moins le temps de sa base", cas[k].nom);
        verifier(c == 1 && g.it_value.tv_sec >= attendu - 1 && g.it_value.tv_sec <= attendu + 1, quoi);
        close(t);
    }
    int t = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    struct itimerspec s = en(0, 1);
    timerfd_settime(t, 0, &s, NULL);
    struct pollfd pf = { t, POLLIN, 0 };
    poll(&pf, 1, 1000);
    uint64_t a = 0;
    struct iovec v[2] = { { &a, 4 }, { (void *)8, 4 } };
    ssize_t n = readv(t, v, 2);
    verifier(n == 4 && a == 1 && erreur(read(t, &a, 8)) == EAGAIN, "readv de 4 octets bons puis 4 fautifs : 4, le compte pris");
    char *z = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(z + 4096, 4096);
    timerfd_settime(t, 0, &s, NULL);
    poll(&pf, 1, 1000);
    n = read(t, z + 4092, 8);
    verifier(n == 4, "read a cheval sur une page absente : les 4 octets copies");
    timerfd_settime(t, 0, &s, NULL);
    poll(&pf, 1, 1000);
    verifier(erreur(read(t, z + 4096, 8)) == EFAULT, "rien de copie : EFAULT");
    munmap(z, 4096);
    close(t);
}

static void surveillance(void)
{
    int t = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK);
    int e = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 42 };
    verifier(epoll_ctl(e, EPOLL_CTL_ADD, t, &ev) == 0, "epoll_ctl ADD d'un timerfd");
    struct itimerspec s = en(0, 15000000);
    timerfd_settime(t, 0, &s, NULL);
    struct epoll_event recu = { 0 };
    verifier(epoll_wait(e, &recu, 1, 1000) == 1 && recu.events == EPOLLIN && recu.data.u64 == 42,
             "epoll_wait : EPOLLIN a l'echeance");
    uint64_t v = 0;
    verifier(read(t, &v, 8) == 8 && v == 1 && epoll_wait(e, &recu, 1, 0) == 0, "lu : plus rien a signaler");
    struct pollfd pf = { t, POLLIN | POLLOUT, 0 };
    verifier(poll(&pf, 1, 0) == 0, "poll sans echeance : ni POLLIN, ni POLLOUT");
    close(e);
    /* Fermé armé : le minuteur est désarmé avec lui (le noyau compte ce
     * qu'il a rendu, « memoire rendue »). */
    s = en(1000000, 1000000);
    timerfd_settime(t, 0, &s, NULL);
    close(t);
}

/* --- Les alarmes : setitimer, getitimer, alarm --- */

static volatile sig_atomic_t alarmes_recues, prof_recus, virt_recus, code_alarme;

static void sur_alarme(int sig, siginfo_t *info, void *contexte)
{
    (void)sig;
    (void)contexte;
    alarmes_recues++;
    code_alarme = info->si_code;
}

static void sur_calcul(int sig)
{
    if (sig == SIGPROF)
        prof_recus++;
    else
        virt_recus++;
}

static int64_t us(struct timeval t)
{
    return (int64_t)t.tv_sec * 1000000 + t.tv_usec;
}

static struct itimerval iv(int64_t intervalle, int64_t valeur)
{
    struct itimerval v = {
        { intervalle / 1000000, intervalle % 1000000 },
        { valeur / 1000000, valeur % 1000000 },
    };
    return v;
}

static struct itimerval lire_alarme(int genre)
{
    struct itimerval v = iv(-1, -1);
    getitimer(genre, &v);
    return v;
}

static void attendre_ms(long ms)
{
    struct timespec d = { ms / 1000, (ms % 1000) * 1000000 };
    while (nanosleep(&d, &d) != 0 && errno == EINTR)
        ;
}

static void alarmes_erreurs(void)
{
    struct itimerval v, faux;
    verifier(erreur(syscall(SYS_getitimer, 3, &v)) == EINVAL, "getitimer d'un genre inconnu : EINVAL");
    verifier(erreur(syscall(SYS_getitimer, ITIMER_REAL, (void *)8)) == EFAULT,
             "getitimer vers une adresse invalide : EFAULT");
    faux = iv(0, 0);
    faux.it_value.tv_usec = 1000000;
    verifier(erreur(syscall(SYS_setitimer, ITIMER_REAL, &faux, NULL)) == EINVAL,
             "setitimer, un million de microsecondes : EINVAL");
    faux = iv(0, 1000);
    faux.it_interval.tv_sec = -1;
    verifier(erreur(syscall(SYS_setitimer, ITIMER_REAL, &faux, NULL)) == EINVAL,
             "setitimer, une periode negative : EINVAL");
    v = iv(0, 1000000);
    verifier(erreur(syscall(SYS_setitimer, 3, &v, NULL)) == EINVAL, "setitimer d'un genre inconnu : EINVAL");
    verifier(erreur(syscall(SYS_setitimer, 3, (void *)8, NULL)) == EFAULT,
             "setitimer : la valeur lue avant le genre (EFAULT)");
    int zero = 1;
    for (int g = ITIMER_REAL; g <= ITIMER_PROF; g++) {
        struct itimerval l = lire_alarme(g);
        zero &= us(l.it_value) == 0 && us(l.it_interval) == 0;
    }
    verifier(zero, "au depart, les trois alarmes desarmees");
    v = iv(0, 10000000);
    verifier(erreur(syscall(SYS_setitimer, ITIMER_REAL, &v, (void *)8)) == EFAULT
             && us(lire_alarme(ITIMER_REAL).it_value) > 9000000,
             "l'ancienne valeur ne s'ecrit pas (EFAULT), l'alarme est pourtant armee");
    struct itimerval ancienne;
    verifier(syscall(SYS_setitimer, ITIMER_REAL, NULL, &ancienne) == 0 && us(ancienne.it_value) > 9000000
             && us(lire_alarme(ITIMER_REAL).it_value) == 0,
             "setitimer sans nouvelle valeur (NULL) : desarmee");
}

static void alarmes_reelles(void)
{
    verifier(alarm(0) == 0, "alarm(0) sans alarme : 0");
    verifier(alarm(5) == 0, "alarm(5) : 0");
    verifier(alarm(3) == 5, "alarm(3) : les 4,99 s qui restaient, arrondies a 5");
    struct itimerval l = lire_alarme(ITIMER_REAL);
    verifier(us(l.it_value) > 2000000 && us(l.it_value) <= 3000000 && us(l.it_interval) == 0,
             "getitimer : moins de 3 s, sans periode");
    verifier(alarm(0) == 3 && us(lire_alarme(ITIMER_REAL).it_value) == 0, "alarm(0) : 3, et desarmee");
    struct itimerval v = iv(0, 300000);
    setitimer(ITIMER_REAL, &v, NULL);
    verifier(alarm(0) == 1, "alarm(0) avec moins d'une seconde a attendre : 1");
    v = iv(0, 1600000);
    setitimer(ITIMER_REAL, &v, NULL);
    verifier(alarm(0) == 2, "1,6 s : arrondies a 2");
    v = iv(0, 1400000);
    setitimer(ITIMER_REAL, &v, NULL);
    verifier(alarm(0) == 1, "1,4 s : arrondies a 1");
    v = iv(1000000, 0);
    setitimer(ITIMER_REAL, &v, NULL);
    l = lire_alarme(ITIMER_REAL);
    verifier(us(l.it_value) == 0 && us(l.it_interval) == 0, "ITIMER_REAL de valeur nulle : sa periode effacee");
    struct itimerval ancienne;
    v = iv(1000000, 2000000);
    setitimer(ITIMER_REAL, &v, NULL);
    v = iv(0, 0);
    setitimer(ITIMER_REAL, &v, &ancienne);
    verifier(us(ancienne.it_interval) == 1000000 && us(ancienne.it_value) > 1900000
             && us(ancienne.it_value) <= 2000000, "setitimer rend l'ancienne : periode et temps restant");
}

static void alarme_periodique(void)
{
    struct sigaction sa = { .sa_sigaction = sur_alarme, .sa_flags = SA_SIGINFO };
    sigaction(SIGALRM, &sa, NULL);
    alarmes_recues = 0;
    code_alarme = 0;
    int64_t debut = ns(CLOCK_MONOTONIC);
    struct itimerval v = iv(10000, 10000);
    setitimer(ITIMER_REAL, &v, NULL);
    while (alarmes_recues < 3 && ns(CLOCK_MONOTONIC) - debut < 2000000000)
        poll(NULL, 0, 20);
    int64_t duree = ns(CLOCK_MONOTONIC) - debut;
    v = iv(0, 0);
    setitimer(ITIMER_REAL, &v, NULL);
    verifier(alarmes_recues >= 3 && duree >= 30000000, "ITIMER_REAL periodique : SIGALRM toutes les 10 ms");
    verifier(code_alarme == SI_KERNEL, "son siginfo : SI_KERNEL, du noyau");
}

static void alarme_bloquee(void)
{
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGALRM);
    sigprocmask(SIG_BLOCK, &m, NULL);
    struct itimerval v = iv(5000, 5000);
    setitimer(ITIMER_REAL, &v, NULL);
    attendre_ms(30);
    struct itimerval l = lire_alarme(ITIMER_REAL);
    verifier(us(l.it_value) == 0 && us(l.it_interval) == 5000,
             "periodique, SIGALRM bloque en attente : arretee (valeur nulle, periode gardee)");
    siginfo_t si;
    struct timespec zero = { 0, 0 };
    verifier(sigtimedwait(&m, &si, &zero) == SIGALRM && si.si_code == SI_KERNEL, "sigtimedwait prend SIGALRM");
    l = lire_alarme(ITIMER_REAL);
    verifier(us(l.it_value) > 0 && us(l.it_value) <= 5000, "SIGALRM pris : l'alarme repart, pour moins d'une periode");
    v = iv(0, 5000);
    setitimer(ITIMER_REAL, &v, NULL);
    attendre_ms(30);
    l = lire_alarme(ITIMER_REAL);
    verifier(us(l.it_value) == 0 && us(l.it_interval) == 0, "une seule fois, echue : valeur nulle");
    verifier(sigtimedwait(&m, &si, &zero) == SIGALRM && us(lire_alarme(ITIMER_REAL).it_value) == 0,
             "et son SIGALRM pris ne la rearme pas");
    sigprocmask(SIG_UNBLOCK, &m, NULL);
}

static void alarme_ignoree(void)
{
    signal(SIGALRM, SIG_IGN);
    struct itimerval v = iv(5000, 5000);
    setitimer(ITIMER_REAL, &v, NULL);
    attendre_ms(30);
    struct itimerval l = lire_alarme(ITIMER_REAL);
    verifier(us(l.it_value) == 0 && us(l.it_interval) == 5000,
             "SIGALRM ignore : jete, jamais pris, la periodique s'arrete");
    v = iv(0, 0);
    setitimer(ITIMER_REAL, &v, NULL);
}

static void alarmes_de_calcul(void)
{
    signal(SIGPROF, sur_calcul);
    signal(SIGVTALRM, sur_calcul);
    struct itimerval v = iv(20000, 20000), ancienne;
    setitimer(ITIMER_PROF, &v, NULL);
    struct itimerval l = lire_alarme(ITIMER_PROF);
    /* Un tic de plus a l'armement (1 ms ici, 4 ms sous WSL) : 30 ms au plus. */
    verifier(us(l.it_value) > 0 && us(l.it_value) <= 30000 && us(l.it_interval) == 20000,
             "ITIMER_PROF : la valeur, en temps de calcul");
    setitimer(ITIMER_VIRTUAL, &v, NULL);
    int64_t debut = ns(CLOCK_MONOTONIC);
    volatile uint64_t x = 0;
    while ((prof_recus < 3 || virt_recus < 3) && ns(CLOCK_MONOTONIC) - debut < 5000000000)
        for (int i = 0; i < 100000; i++)
            x += i;
    v = iv(0, 0);
    setitimer(ITIMER_VIRTUAL, &v, NULL);
    setitimer(ITIMER_PROF, &v, &ancienne);
    verifier(prof_recus >= 3 && virt_recus >= 3, "en calculant : SIGPROF et SIGVTALRM, toutes les 20 ms");
    verifier(us(ancienne.it_interval) == 20000, "desarmee : sa periode rendue");
    v = iv(1000000, 0);
    setitimer(ITIMER_VIRTUAL, &v, NULL);
    l = lire_alarme(ITIMER_VIRTUAL);
    verifier(us(l.it_value) == 0 && us(l.it_interval) == 1000000,
             "ITIMER_VIRTUAL de valeur nulle : desarmee, sa periode gardee (pas comme ITIMER_REAL)");
    v = iv(0, 0);
    setitimer(ITIMER_VIRTUAL, &v, NULL);
}

/* Les minuteurs POSIX, par les appels eux-mêmes (la glibc traduit les
 * numéros de ses minuteurs SIGEV_THREAD). */
static long tc(clockid_t h, struct sigevent *ev, int *id) { return syscall(SYS_timer_create, h, ev, id); }
static long ts(int id, int drapeaux, const struct itimerspec *s, struct itimerspec *a)
{
    return syscall(SYS_timer_settime, id, drapeaux, s, a);
}
static long tg(int id, struct itimerspec *s) { return syscall(SYS_timer_gettime, id, s); }
static long tover(int id) { return syscall(SYS_timer_getoverrun, id); }
static long tdel(int id) { return syscall(SYS_timer_delete, id); }

static struct sigevent sev(int notification, int sig, long valeur)
{
    struct sigevent e;
    memset(&e, 0, sizeof e);
    e.sigev_notify = notification;
    e.sigev_signo = sig;
    e.sigev_value.sival_ptr = (void *)valeur;
    return e;
}

/* Le signal `sig` attend-il ? */
static int en_attente(int sig)
{
    sigset_t e;
    sigpending(&e);
    return sigismember(&e, sig);
}

/* Prend `sig` (bloqué) s'il attend, sans attendre : 0 sinon. */
static int prendre(int sig, siginfo_t *info)
{
    sigset_t e;
    sigemptyset(&e);
    sigaddset(&e, sig);
    struct timespec zero = { 0, 0 };
    return sigtimedwait(&e, info, &zero) == sig;
}

static void bloquer(int sig, int oui)
{
    sigset_t e;
    sigemptyset(&e);
    sigaddset(&e, sig);
    sigprocmask(oui ? SIG_BLOCK : SIG_UNBLOCK, &e, NULL);
}

static void posix_erreurs(void)
{
    int id = -1, a, b;
    struct sigevent e = sev(SIGEV_NONE, 0, 0);
    verifier(erreur(tc(99, &e, &id)) == EINVAL, "timer_create, horloge inconnue : EINVAL");
    verifier(erreur(tc(99, (void *)8, &id)) == EFAULT, "sigevent illisible (lu avant l'horloge) : EFAULT");
    verifier(erreur(tc(CLOCK_MONOTONIC_RAW, &e, &id)) == EOPNOTSUPP
             && erreur(tc(CLOCK_REALTIME_COARSE, &e, &id)) == EOPNOTSUPP, "MONOTONIC_RAW, REALTIME_COARSE : EOPNOTSUPP");
    verifier(tc(CLOCK_MONOTONIC, &e, &a) == 0, "SIGEV_NONE, signal 0 : cree");
    e = sev(3, SIGUSR1, 0);
    verifier(erreur(tc(CLOCK_MONOTONIC, &e, &id)) == EINVAL, "sigev_notify 3 : EINVAL");
    e = sev(SIGEV_SIGNAL, 65, 0);
    verifier(erreur(tc(CLOCK_MONOTONIC, &e, &id)) == EINVAL, "signal 65 : EINVAL");
    e = sev(SIGEV_THREAD_ID, SIGUSR1, 0);
    e._sigev_un._tid = 999999;
    verifier(erreur(tc(CLOCK_MONOTONIC, &e, &id)) == EINVAL, "SIGEV_THREAD_ID d'un fil inconnu : EINVAL");
    e = sev(SIGEV_NONE, 0, 0);
    verifier(erreur(tc(CLOCK_MONOTONIC, &e, (void *)8)) == EFAULT, "numero vers une adresse invalide : EFAULT");
    verifier(erreur(tc(CLOCK_REALTIME_ALARM, &e, &id)) == EPERM, "CLOCK_REALTIME_ALARM : EPERM");
    verifier(tc(CLOCK_MONOTONIC, &e, &b) == 0 && b == a + 6,
             "chaque echec apres le numero le consomme : le suivant a son numero + 6");
    struct itimerspec s = en(0, 0);
    verifier(erreur(ts(b, 0, NULL, NULL)) == EINVAL, "timer_settime sans valeur : EINVAL");
    verifier(erreur(ts(999, 0, (void *)8, NULL)) == EFAULT, "valeur illisible (lue avant le numero) : EFAULT");
    s.it_value.tv_nsec = 1000000000;
    verifier(erreur(ts(999, 0, &s, NULL)) == EINVAL && erreur(ts(b, 0, &s, NULL)) == EINVAL,
             "nanosecondes a 10^9 : EINVAL");
    s = en(0, 1000);
    verifier(erreur(ts(999, 0, &s, NULL)) == EINVAL && erreur(ts(-1, 0, &s, NULL)) == EINVAL,
             "numero inconnu, negatif : EINVAL");
    verifier(erreur(tg(999, &s)) == EINVAL && erreur(tg(b, (void *)8)) == EFAULT,
             "timer_gettime : numero inconnu EINVAL, adresse invalide EFAULT");
    verifier(erreur(tover(999)) == EINVAL && tover(b) == 0, "timer_getoverrun : EINVAL, 0 avant tout signal");
    s = en(0, 10000000000LL);
    verifier(erreur(ts(b, 0xfe, &s, (void *)8)) == EFAULT && tg(b, &s) == 0 && en_ns(s.it_value) > 9000000000LL,
             "ancienne valeur illisible : EFAULT, mais arme (drapeaux inconnus ignores)");
    s.it_value.tv_sec = INT64_MAX;
    verifier(ts(b, 0, &s, NULL) == 0 && tg(b, &s) == 0 && s.it_value.tv_sec <= 9223372036LL
             && s.it_value.tv_sec > 9223372036LL - 100000000, "arme pour plus de 292 ans : ramene a KTIME_MAX");
    verifier(tdel(a) == 0 && tdel(b) == 0 && erreur(tdel(a)) == EINVAL, "timer_delete, puis une seconde fois : EINVAL");

    struct rlimit l, zero = { 0, 0 };
    getrlimit(RLIMIT_SIGPENDING, &l);
    zero.rlim_max = l.rlim_max;
    setrlimit(RLIMIT_SIGPENDING, &zero);
    verifier(erreur(tc(CLOCK_MONOTONIC, &e, &id)) == EAGAIN, "RLIMIT_SIGPENDING a 0 : EAGAIN (son siginfo est compte)");
    setrlimit(RLIMIT_SIGPENDING, &l);
}

static void posix_signaux(void)
{
    int id;
    siginfo_t info;
    struct itimerspec s;

    /* Sans sigevent : SIGALRM, si_value = le numéro. */
    bloquer(SIGALRM, 1);
    tc(CLOCK_MONOTONIC, NULL, &id);
    s = en(0, 10000000);
    ts(id, 0, &s, NULL);
    attendre_ms(30);
    verifier(prendre(SIGALRM, &info) && info.si_code == SI_TIMER && info.si_timerid == id
             && info.si_value.sival_int == id && info.si_overrun == 0,
             "sans sigevent : SIGALRM, SI_TIMER, si_timerid et si_value = le numero");
    tdel(id);
    bloquer(SIGALRM, 0);

    /* Périodique, bloqué : ses échéances se fondent en un signal, comptées. */
    int sig = SIGRTMIN + 1;
    bloquer(sig, 1);
    struct sigevent e = sev(SIGEV_SIGNAL, sig, 1234);
    tc(CLOCK_MONOTONIC, &e, &id);
    int64_t periode = 10000000, avant = ns(CLOCK_MONOTONIC);
    s = en(periode, periode);
    ts(id, 0, &s, NULL);
    int64_t apres = ns(CLOCK_MONOTONIC);
    attendre_ms(55);
    verifier(tg(id, &s) == 0 && en_ns(s.it_value) > 0 && en_ns(s.it_value) <= periode && en_ns(s.it_interval) == periode,
             "periodique bloque : timer_gettime dans ]0, periode]");
    verifier(tover(id) == 0, "... timer_getoverrun 0 avant que le signal soit pris");
    int64_t t1 = ns(CLOCK_MONOTONIC);
    int pris = prendre(sig, &info);
    int64_t t2 = ns(CLOCK_MONOTONIC);
    int64_t bas = (t1 - apres - periode) / periode, haut = (t2 - avant - periode) / periode;
    verifier(pris && info.si_value.sival_ptr == (void *)1234 && info.si_overrun >= bas && info.si_overrun <= haut
             && tover(id) == info.si_overrun, "... pris : si_overrun compte les echeances fondues, timer_getoverrun aussi");
    attendre_ms(25);
    verifier(prendre(sig, &info), "... et le minuteur est reparti");

    /* Un signal en attente d'un armement passé est périmé. */
    s = en(0, 10000000);
    ts(id, 0, &s, NULL);
    attendre_ms(30);
    s = en(0, 10000000000LL);
    ts(id, 0, &s, NULL);
    verifier(en_attente(sig) && !prendre(sig, &info), "rearme : le signal en attente est perime (sigpending le montre)");
    s = en(0, 10000000);
    ts(id, 0, &s, NULL);
    attendre_ms(30);
    tdel(id);
    verifier(en_attente(sig) && !prendre(sig, &info), "detruit : de meme");
    bloquer(sig, 0);

    /* SIGEV_NONE : jamais de signal, on le lit. */
    e = sev(SIGEV_NONE, 0, 0);
    tc(CLOCK_MONOTONIC, &e, &id);
    s = en(0, 10000000);
    ts(id, 0, &s, NULL);
    attendre_ms(25);
    verifier(tg(id, &s) == 0 && en_ns(s.it_value) == 0, "SIGEV_NONE, une fois, echu : 0");
    s = en(periode, periode);
    ts(id, 0, &s, NULL);
    attendre_ms(35);
    verifier(tg(id, &s) == 0 && en_ns(s.it_value) > 0 && en_ns(s.it_value) <= periode && tover(id) == 0,
             "SIGEV_NONE periodique : avance dans ]0, periode], aucun depassement rendu");
    s = en(0, 10000000000LL);
    ts(id, 0, &s, NULL);
    s = en(0, 0);
    ts(id, 0, &s, NULL);
    verifier(tg(id, &s) == 0 && en_ns(s.it_value) > 9000000000LL,
             "SIGEV_NONE desarme : il rend encore ce qui restait (son echeance est gardee)");
    tdel(id);

    /* Vers un fil : SIGEV_THREAD_ID. */
    sig = SIGRTMIN + 2;
    bloquer(sig, 1);
    e = sev(SIGEV_THREAD_ID, sig, 0);
    e._sigev_un._tid = gettid();
    verifier(tc(CLOCK_REALTIME, &e, &id) == 0, "SIGEV_THREAD_ID vers soi-meme : cree");
    struct timespec date;
    clock_gettime(CLOCK_REALTIME, &date);
    s = en(0, (int64_t)date.tv_sec * 1000000000 + date.tv_nsec + 10000000);
    ts(id, TIMER_ABSTIME, &s, NULL);
    attendre_ms(30);
    verifier(prendre(sig, &info) && info.si_timerid == id, "... une echeance absolue de la date : le signal au fil");
    tdel(id);
    bloquer(sig, 0);
}

static volatile sig_atomic_t posix_recus;
static void sur_posix(int sig)
{
    (void)sig;
    posix_recus++;
}

/* Les périodes d'un minuteur périodique : chaque signal compte la sienne et
 * celles qu'il a sautées (si_overrun) ; le gestionnaire note aussi le temps
 * de calcul où il les voit (clock_gettime est sûr dans un gestionnaire). */
static volatile sig_atomic_t posix_periodes, posix_assez;
static volatile int64_t posix_vu;
static clockid_t posix_horloge;
static void sur_posix_periode(int sig, siginfo_t *i, void *c)
{
    (void)sig;
    (void)c;
    posix_periodes += 1 + i->si_overrun;
    posix_vu = ns(posix_horloge);
    if (posix_periodes >= 5)
        posix_assez = 1;
}

static void posix_ignores(void)
{
    int id, sig = SIGRTMIN + 3;
    struct itimerspec s;
    struct sigaction a = { 0 };
    a.sa_handler = SIG_IGN;
    sigaction(sig, &a, NULL);
    struct sigevent e = sev(SIGEV_SIGNAL, sig, 0);
    tc(CLOCK_MONOTONIC, &e, &id);
    s = en(10000000, 10000000);
    ts(id, 0, &s, NULL);
    attendre_ms(35);
    verifier(tg(id, &s) == 0 && en_ns(s.it_value) > 0 && en_ns(s.it_value) <= 10000000 && !en_attente(sig),
             "periodique ignore : mis de cote, rien en attente, timer_gettime dans ]0, periode]");
    posix_recus = 0;
    a.sa_handler = sur_posix;
    sigaction(sig, &a, NULL);
    /* Au moins un : livré au retour de sigaction. Pas « exactement un » : la
     * période suivante tombe 10 ms plus tard, et une machine qui perd le
     * processeur ce temps-là entre le retour et ce regard en livre un
     * second (vu une fois sous le Linux de référence chargé par deux
     * vérifications). */
    verifier(posix_recus >= 1, "... un gestionnaire remplace SIG_IGN : son signal revient, livre tout de suite");
    attendre_ms(35);
    verifier(posix_recus >= 2, "... et le minuteur est reparti");
    /* En attente (bloqué), effacé par SIG_IGN : mis de côté aussi. */
    bloquer(sig, 1);
    attendre_ms(25);
    a.sa_handler = SIG_IGN;
    sigaction(sig, &a, NULL);
    int efface = !en_attente(sig);
    a.sa_handler = sur_posix;
    sigaction(sig, &a, NULL);
    verifier(efface && en_attente(sig), "periodique en attente efface par SIG_IGN : il revient au gestionnaire suivant");
    tdel(id);
    bloquer(sig, 0);
    /* Une seule fois, ignoré : perdu. */
    a.sa_handler = SIG_IGN;
    sigaction(sig, &a, NULL);
    tc(CLOCK_MONOTONIC, &e, &id);
    s = en(0, 10000000);
    ts(id, 0, &s, NULL);
    attendre_ms(25);
    posix_recus = 0;
    a.sa_handler = sur_posix;
    sigaction(sig, &a, NULL);
    verifier(posix_recus == 0 && tg(id, &s) == 0 && en_ns(s.it_value) == 0, "une seule fois, ignore : perdu");
    tdel(id);
}

/* Calcule jusqu'à `fini` ou `limite` ns de calcul. */
/* Les bases des minuteurs du temps (voir `bornes`) : un TAI relatif reste
 * dans la sienne (KTIME_MAX moins TAI), un REALTIME relatif va dans
 * MONOTONIC ; et une échéance absolue d'avant le démarrage compte ses
 * périodes depuis elle : la suivante tombe à la seconde ronde de la date. */
static void posix_bornes(void)
{
    const int64_t ktime_max_s = INT64_MAX / 1000000000;
    struct sigevent e = sev(SIGEV_NONE, 0, 0);
    struct itimerspec s = { { 0, 0 }, { INT64_MAX, 0 } }, g;
    int id;
    clockid_t horloges[] = { CLOCK_TAI, CLOCK_REALTIME }, bases[] = { CLOCK_TAI, CLOCK_MONOTONIC };
    const char *noms[] = { "TAI relatif de LONG_MAX s : KTIME_MAX moins TAI", "REALTIME relatif de LONG_MAX s : KTIME_MAX moins MONOTONIC" };
    for (int k = 0; k < 2; k++) {
        tc(horloges[k], &e, &id);
        ts(id, 0, &s, NULL);
        tg(id, &g);
        int64_t attendu = ktime_max_s - ns(bases[k]) / 1000000000;
        verifier(g.it_value.tv_sec >= attendu - 1 && g.it_value.tv_sec <= attendu + 1, noms[k]);
        tdel(id);
    }
    tc(CLOCK_REALTIME, &e, &id);
    s = en(1000000000LL, 1000000000LL);
    ts(id, TIMER_ABSTIME, &s, NULL);
    struct timespec reel;
    tg(id, &g);
    clock_gettime(CLOCK_REALTIME, &reel);
    int64_t ecart = (en_ns(g.it_value) - (1000000000 - reel.tv_nsec) % 1000000000 + 1000000000) % 1000000000;
    verifier(g.it_value.tv_sec == 0 && (ecart < 20000000 || ecart > 980000000),
             "REALTIME absolu a 1 s apres 1970, toutes les secondes : la suivante a la seconde ronde de la date");
    tdel(id);
}

static void calculer(volatile sig_atomic_t *fini, int64_t limite, clockid_t h)
{
    int64_t debut = ns(h);
    while (!*fini && ns(h) - debut < limite)
        ;
}

static void posix_calcul(void)
{
    int id, sig = SIGRTMIN + 4;
    struct itimerspec s;
    struct sigaction a = { 0 };
    a.sa_handler = sur_posix;
    sigaction(sig, &a, NULL);
    struct sigevent e = sev(SIGEV_SIGNAL, sig, 0);
    /* Les deux horloges nommées par l'appel brut (2 et 3), puis par la
     * glibc, qui passe -6 et -2 (le pid 0 encodé, SCHED) ; puis PROF du
     * processus et VIRT du fil (comptées au tic), encodées à la main
     * (posix-cpu-timers.c : le pid complémenté, décalé de trois bits, le
     * bit 2 pour un fil, la mesure dans les bits 0 et 1). */
    clockid_t horloges[] = { CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID,
                             (clockid_t)(~0u << 3 | 0), (clockid_t)(~0u << 3 | 4 | 1) };
    const char *noms[] = { "CLOCK_PROCESS_CPUTIME_ID", "CLOCK_THREAD_CPUTIME_ID", "CLOCK_PROCESS_CPUTIME_ID par la glibc",
                           "CLOCK_THREAD_CPUTIME_ID par la glibc", "PROF du processus", "VIRT du fil" };
    for (int k = 0; k < 6; k++) {
        char quoi[160];
        if (k == 2 || k == 3) {
            /* Le numéro du noyau, que la glibc rend tel quel pour
             * SIGEV_SIGNAL. */
            timer_t t;
            snprintf(quoi, sizeof quoi, "%s : timer_create", noms[k]);
            verifier(timer_create(horloges[k], &e, &t) == 0, quoi);
            id = (int)(intptr_t)t;
        } else {
            tc(horloges[k], &e, &id);
        }
        posix_recus = 0;
        int64_t debut = ns(horloges[k]);
        s = en(0, 20000000);
        ts(id, 0, &s, NULL);
        calculer(&posix_recus, 2000000000, horloges[k]);
        int64_t calcule = ns(horloges[k]) - debut;
        snprintf(quoi, sizeof quoi, "%s, 20 ms de calcul : le signal, apres au moins 20 ms", noms[k]);
        verifier(posix_recus == 1 && calcule >= 20000000, quoi);
        snprintf(quoi, sizeof quoi, "%s : echu, une fois, plus rien (periode comprise)", noms[k]);
        verifier(tg(id, &s) == 0 && en_ns(s.it_value) == 0, quoi);
        /* Périodique : 10 ms de calcul. Un processeur virtuel que l'hôte
         * suspend (une machine chargée) compte d'un coup au programme qui
         * tournait tout le temps manqué : plusieurs périodes passent en un
         * tic, et Linux n'en envoie qu'un signal, les autres dans si_overrun
         * (`bump_cpu_timer`, au réarmement). Le compte qui ne dépend pas de
         * la charge est donc celui des périodes, signaux et dépassements
         * ensemble : on calcule jusqu'à cinq, et elles doivent suivre le
         * temps de calcul (à une près : le départ est lu après l'armement,
         * le gestionnaire après le réarmement). */
        struct sigaction p = { 0 };
        p.sa_sigaction = sur_posix_periode;
        p.sa_flags = SA_SIGINFO;
        posix_periodes = 0;
        posix_assez = 0;
        posix_horloge = horloges[k];
        sigaction(sig, &p, NULL);
        s = en(10000000, 10000000);
        ts(id, 0, &s, NULL);
        int64_t depart = ns(horloges[k]);
        calculer(&posix_assez, 2000000000, horloges[k]);
        int64_t rythme = (posix_vu - depart) / 10000000;
        snprintf(quoi, sizeof quoi, "%s periodique de 10 ms : cinq periodes (signaux et si_overrun), au rythme du calcul", noms[k]);
        verifier(posix_periodes >= 5 && posix_periodes - rythme <= 1 && rythme - posix_periodes <= 1, quoi);
        sigaction(sig, &a, NULL);
        /* Une échéance absolue déjà passée : tout de suite, sans calculer. */
        bloquer(sig, 1);
        s = en(0, 1);
        ts(id, TIMER_ABSTIME, &s, NULL);
        snprintf(quoi, sizeof quoi, "%s, echeance absolue passee : le signal tout de suite", noms[k]);
        verifier(en_attente(sig), quoi);
        siginfo_t info;
        prendre(sig, &info);
        bloquer(sig, 0);
        tdel(id);
    }
    /* Le processus finit avec un minuteur arme : détruit avec lui. */
    e = sev(SIGEV_NONE, 0, 0);
    tc(CLOCK_MONOTONIC, &e, &id);
    s = en(0, 3600000000000LL);
    ts(id, 0, &s, NULL);
}

int main(void)
{
    creation();
    une_fois();
    periodique();
    bornes();
    surveillance();
    alarmes_erreurs();
    alarmes_reelles();
    alarme_periodique();
    alarme_bloquee();
    alarme_ignoree();
    alarmes_de_calcul();
    posix_erreurs();
    posix_signaux();
    posix_ignores();
    posix_bornes();
    posix_calcul();
    /* Le processus finit son alarme armee : desarmee avec lui (le noyau
     * compte ce qu'il a rendu, « memoire rendue »). */
    alarm(3600);
    printf("[linux] minuteurs : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
