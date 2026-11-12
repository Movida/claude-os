/*
 * Les minuteurs (les soldes d'avant 6k) : timerfd, un minuteur derrière un
 * descripteur, qu'attend une boucle d'événements bâtie sur epoll. Il
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

int main(void)
{
    creation();
    une_fois();
    periodique();
    bornes();
    surveillance();
    printf("[linux] minuteurs : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
