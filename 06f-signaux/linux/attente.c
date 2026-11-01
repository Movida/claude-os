/*
 * Attendre plusieurs fichiers à la fois (6f) : poll, ppoll, select,
 * pselect6 et epoll, contre ce qu'en fait Linux 6.18 (mesuré). Ce que rend le
 * sondage de chaque sorte de fichier, les erreurs dans leur ordre, les
 * délais et le temps restant écrit, le masque de ppoll et pselect6, et
 * l'attente elle-même : un autre fil qui écrit un eventfd réveille le fil
 * qui attend, deux fils qui attendent le même sont réveillés tous les deux,
 * et un numéro fermé pendant l'attente par un autre fil ne fait pas
 * disparaître le fichier sous elle. Pour epoll : par front (EPOLLET), par
 * niveau, EPOLLONESHOT, les epolls emboîtés, l'inscription qui survit à un
 * dup puis disparaît au dernier close, les erreurs d'epoll_wait ; dix mille
 * écritures d'un autre fil en EPOLLET sans en perdre une, et un fil qui
 * ferme et rouvre des eventfd surveillés pendant l'attente. Sur l'hôte comme
 * chez nous.
 *
 * Par les appels bruts (syscall) là où la glibc cache ce que fait le noyau :
 * son ppoll et son pselect travaillent sur une copie du délai (le temps
 * restant n'est pas écrit), et son select passe par pselect6.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] attente : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static long long maintenant_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}

static void dormir_ms(int ms)
{
    struct timespec t = { 0, ms * 1000000L };
    nanosleep(&t, NULL);
}

/* Ce que rend poll pour chaque sorte de fichier qui existe chez nous
 * (events = 0xffff : tout est demandé). */
static void sortes(void)
{
    char nom[64];
    snprintf(nom, sizeof nom, "/tmp/attente-%d", getpid());
    int fn = open("/dev/null", O_RDWR), fz = open("/dev/zero", O_RDONLY), fr = open("/dev/random", O_RDONLY),
        fu = open("/dev/urandom", O_RDONLY), ff = open(nom, O_RDWR | O_CREAT | O_TRUNC, 0600), fd = open("/tmp", O_RDONLY),
        fp = open("/tmp", O_PATH), fm = open("/proc/self/maps", O_RDONLY), e1 = eventfd(1, 0), e0 = eventfd(0, 0);
    unlink(nom);
    int ferme = dup(fn);
    close(ferme);
    struct pollfd p[] = {
        { fn, -1, 0 }, { fz, -1, 0 }, { fr, -1, 0 }, { fu, -1, 0 }, { ff, -1, 0 }, { fd, -1, 0 }, { fp, -1, 0 },
        { fm, -1, 0 }, { e1, -1, 0 }, { e0, -1, 0 }, { ferme, POLLIN, 0 }, { -5, POLLIN, 0 }, { ff, 0, 0 },
    };
    int n = poll(p, sizeof p / sizeof *p, 0);
    static const short attendu[] = { 0x145, 0x145, 0x41, 0x145, 0x145, 0x145, 0x20, 0x145, 0x5, 0x4, 0x20, 0, 0 };
    int ok = n == 11;
    for (unsigned i = 0; i < sizeof p / sizeof *p; i++) {
        ok &= p[i].revents == attendu[i];
        if (p[i].revents != attendu[i])
            printf("[linux] attente : (entree %u : revents %#x, attendu %#x)\n", i, p[i].revents, attendu[i]);
    }
    verifier(ok, "poll de chaque sorte : null, zero, urandom, fichier, dossier, /proc 0x145 ; random 0x41 ; eventfd 0x5 et 0x4 ; O_PATH et ferme POLLNVAL ; negatif, events nuls 0");
    verifier(p[10].fd == ferme && p[10].events == POLLIN && p[12].fd == ff && p[12].events == 0,
             "poll n'ecrit que revents (fd et events gardes)");
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    errno = 0;
    long r = syscall(SYS_poll, p, rl.rlim_cur + 1, 0);
    verifier(r == -1 && errno == EINVAL, "poll de plus de RLIMIT_NOFILE entrees : EINVAL");
    errno = 0;
    r = syscall(SYS_poll, NULL, 1, 0);
    verifier(r == -1 && errno == EFAULT, "poll d'un tableau a l'adresse 0 : EFAULT");
    long long t0 = maintenant_ms();
    r = poll(NULL, 0, 50);
    verifier(r == 0 && maintenant_ms() - t0 >= 50, "poll de rien pendant 50 ms : 0, apres 50 ms");
    struct pollfd q = { e0, POLLIN, 0 };
    t0 = maintenant_ms();
    r = poll(&q, 1, 100);
    verifier(r == 0 && q.revents == 0 && maintenant_ms() - t0 >= 100, "poll d'un eventfd vide pendant 100 ms : 0, apres 100 ms");
    for (unsigned i = 0; i < sizeof p / sizeof *p - 3; i++)
        close(p[i].fd);
}

/* Un autre fil qui écrit (ou lit) un eventfd après 50 ms. */
static int cible_efd;
static int lire_au_lieu_d_ecrire;

static void *ecrire_plus_tard(void *rien)
{
    (void)rien;
    dormir_ms(50);
    uint64_t v = 1;
    if (lire_au_lieu_d_ecrire ? read(cible_efd, &v, 8) != 8 : write(cible_efd, &v, 8) != 8)
        printf("[linux] attente : l'autre fil n'a pas pu se servir de l'eventfd : ECHEC\n");
    return NULL;
}

static int attendus_ensemble;
static void *poll_en_parallele(void *rien)
{
    (void)rien;
    struct pollfd q = { cible_efd, POLLIN, 0 };
    if (poll(&q, 1, -1) == 1 && q.revents == POLLIN)
        __atomic_add_fetch(&attendus_ensemble, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static int numero_ferme, double_du_numero;
static void *fermer_puis_ecrire(void *rien)
{
    (void)rien;
    dormir_ms(50);
    close(numero_ferme);
    dormir_ms(20);
    uint64_t v = 1;
    if (write(double_du_numero, &v, 8) != 8)
        printf("[linux] attente : ecriture du double : ECHEC\n");
    return NULL;
}

static void reveils(void)
{
    pthread_t t;
    cible_efd = eventfd(0, 0);
    lire_au_lieu_d_ecrire = 0;
    pthread_create(&t, NULL, ecrire_plus_tard, NULL);
    struct pollfd q = { cible_efd, POLLIN, 0 };
    long long t0 = maintenant_ms();
    int r = poll(&q, 1, -1);
    pthread_join(t, NULL);
    verifier(r == 1 && q.revents == POLLIN && maintenant_ms() - t0 >= 50, "poll sans delai, un autre fil ecrit l'eventfd : reveille, POLLIN");
    close(cible_efd);

    /* Le compteur au plus haut : pas de POLLOUT, jusqu'à ce qu'un autre fil
     * le lise (le réveil porte POLLOUT). */
    cible_efd = eventfd(0, 0);
    uint64_t presque = 0xfffffffffffffffeull;
    if (write(cible_efd, &presque, 8) != 8)
        printf("[linux] attente : remplir l'eventfd : ECHEC\n");
    lire_au_lieu_d_ecrire = 1;
    pthread_create(&t, NULL, ecrire_plus_tard, NULL);
    q = (struct pollfd){ cible_efd, POLLOUT, 0 };
    r = poll(&q, 1, 2000);
    pthread_join(t, NULL);
    verifier(r == 1 && q.revents == POLLOUT, "poll de POLLOUT d'un eventfd plein, un autre fil le lit : reveille, POLLOUT");
    close(cible_efd);

    /* Deux fils attendent le même eventfd : une écriture les réveille tous
     * les deux (des entrées ordinaires). */
    cible_efd = eventfd(0, 0);
    attendus_ensemble = 0;
    pthread_t a, b;
    pthread_create(&a, NULL, poll_en_parallele, NULL);
    pthread_create(&b, NULL, poll_en_parallele, NULL);
    dormir_ms(50);
    uint64_t un = 1;
    if (write(cible_efd, &un, 8) != 8)
        printf("[linux] attente : ecriture : ECHEC\n");
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    verifier(attendus_ensemble == 2, "deux fils dans poll du meme eventfd : une ecriture les reveille tous les deux");
    close(cible_efd);

    /* Le numéro attendu fermé par un autre fil pendant poll : le fichier
     * reste (l'entrée le tient, et un double aussi) ; l'écriture par le
     * double réveille poll, qui resonde : le numéro est fermé, POLLNVAL. */
    numero_ferme = eventfd(0, 0);
    double_du_numero = dup(numero_ferme);
    pthread_create(&t, NULL, fermer_puis_ecrire, NULL);
    q = (struct pollfd){ numero_ferme, POLLIN, 0 };
    r = poll(&q, 1, 2000);
    pthread_join(t, NULL);
    verifier(r == 1 && q.revents == POLLNVAL, "le numero ferme par un autre fil pendant poll : reveille par une ecriture du double, POLLNVAL");
    close(double_du_numero);
}

static volatile int appels;
static uint64_t masque_du_cadre;

static void gestionnaire(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    memcpy(&masque_du_cadre, &uc->uc_sigmask, 8);
    appels++;
}

static int usr1_en_attente(void)
{
    sigset_t m;
    sigpending(&m);
    return sigismember(&m, SIGUSR1);
}

static uint64_t masque(void)
{
    sigset_t m;
    sigprocmask(SIG_BLOCK, NULL, &m);
    uint64_t v;
    memcpy(&v, &m, 8);
    return v;
}

#define B(s) (1ull << ((s) - 1))

static void masques(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = gestionnaire;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t usr1, vide;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigemptyset(&vide);
    sigprocmask(SIG_BLOCK, &usr1, NULL);
    int pret = eventfd(1, 0), vide_efd = eventfd(0, 0);

    /* Quelque chose de prêt : le masque d'avant revient avant la sortie, le
     * signal qu'il bloque n'est pas livré. */
    raise(SIGUSR1);
    appels = 0;
    struct pollfd q = { pret, POLLIN, 0 };
    struct timespec ts = { 1, 0 };
    long r = syscall(SYS_ppoll, &q, 1, &ts, &vide, 8);
    verifier(r == 1 && appels == 0 && usr1_en_attente() && masque() == B(SIGUSR1),
             "ppoll pret, SIGUSR1 en attente que seul le masque de ppoll laisse passer : 1, pas livre, toujours en attente");

    /* Rien de prêt : le signal est livré pendant ppoll, avec le masque
     * d'avant dans son cadre ; EINTR, et le temps restant écrit. */
    appels = 0;
    q = (struct pollfd){ vide_efd, POLLIN, 0 };
    ts = (struct timespec){ 1, 0 };
    r = syscall(SYS_ppoll, &q, 1, &ts, &vide, 8);
    long long reste = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
    verifier(r == -1 && errno == EINTR && appels == 1 && masque_du_cadre == B(SIGUSR1) && masque() == B(SIGUSR1)
             && reste > 500 && reste <= 1000,
             "ppoll, rien de pret, SIGUSR1 debloque par son masque : livre (le masque d'avant dans le cadre), EINTR, le reste ecrit");

    ts = (struct timespec){ 0, 200000000 };
    r = syscall(SYS_ppoll, &q, 1, &ts, NULL, 8);
    verifier(r == 0 && ts.tv_sec == 0 && ts.tv_nsec == 0, "ppoll de 0,2 s sans rien de pret : 0, le reste ecrit a zero");
    errno = 0;
    r = syscall(SYS_ppoll, &q, 1, NULL, &vide, 7);
    verifier(r == -1 && errno == EINVAL, "ppoll, un masque de 7 octets : EINVAL");
    ts = (struct timespec){ 0, 1000000000 };
    errno = 0;
    r = syscall(SYS_ppoll, &q, 1, &ts, NULL, 8);
    verifier(r == -1 && errno == EINVAL, "ppoll, des nanosecondes a 1e9 : EINVAL");
    errno = 0;
    r = syscall(SYS_ppoll, &q, 1, (void *)8, NULL, 8);
    verifier(r == -1 && errno == EFAULT, "ppoll, un delai a l'adresse 8 : EFAULT");

    /* pselect6, son sixième argument : {masque, taille}. */
    appels = 0;
    raise(SIGUSR1);
    fd_set l;
    FD_ZERO(&l);
    FD_SET(vide_efd, &l);
    ts = (struct timespec){ 1, 0 };
    struct { const sigset_t *m; size_t t; } paire = { &vide, 8 };
    r = syscall(SYS_pselect6, vide_efd + 1, &l, NULL, NULL, &ts, &paire);
    verifier(r == -1 && errno == EINTR && appels == 1 && FD_ISSET(vide_efd, &l) && masque() == B(SIGUSR1),
             "pselect6 sous un masque qui laisse passer SIGUSR1 : livre, EINTR, l'ensemble laisse tel quel");
    errno = 0;
    r = syscall(SYS_pselect6, vide_efd + 1, &l, NULL, NULL, &ts, (void *)8);
    verifier(r == -1 && errno == EFAULT, "pselect6, la paire du masque a l'adresse 8 : EFAULT");

    while (usr1_en_attente()) {
        sigset_t m;
        sigemptyset(&m);
        sigaddset(&m, SIGUSR1);
        int s;
        sigwait(&m, &s);
    }
    sigprocmask(SIG_UNBLOCK, &usr1, NULL);
    signal(SIGUSR1, SIG_DFL);
    close(pret);
    close(vide_efd);
}

static long brut_select(int n, void *l, void *e, void *x, struct timeval *tv)
{
    return syscall(SYS_select, n, l, e, x, tv);
}

static void selects(void)
{
    int pret = eventfd(1, 0), vide = eventfd(0, 0), chemin = open("/tmp", O_PATH);
    fd_set l, ecr;
    FD_ZERO(&l);
    FD_ZERO(&ecr);
    FD_SET(pret, &l);
    FD_SET(vide, &l);
    FD_SET(vide, &ecr);
    struct timeval tv = { 0, 0 };
    int n = (pret > vide ? pret : vide) + 1;
    long r = brut_select(n, &l, &ecr, NULL, &tv);
    verifier(r == 2 && FD_ISSET(pret, &l) && !FD_ISSET(vide, &l) && FD_ISSET(vide, &ecr),
             "select : un eventfd a 1 pret a lire, un vide pret a ecrire seulement ; 2");

    int ferme = dup(vide);
    close(ferme);
    FD_ZERO(&l);
    FD_SET(ferme, &l);
    errno = 0;
    r = brut_select(ferme + 1, &l, NULL, NULL, &tv);
    verifier(r == -1 && errno == EBADF, "select d'un numero ferme : EBADF");
    FD_ZERO(&l);
    FD_ZERO(&ecr);
    FD_SET(chemin, &l);
    FD_SET(chemin, &ecr);
    r = brut_select(chemin + 1, &l, &ecr, NULL, &tv);
    verifier(r == 2 && FD_ISSET(chemin, &l) && FD_ISSET(chemin, &ecr),
             "select d'un O_PATH en lecture et en ecriture : pas d'EBADF, mais POLLNVAL, rendu pret deux fois");
    errno = 0;
    r = brut_select(-1, NULL, NULL, NULL, &tv);
    verifier(r == -1 && errno == EINVAL, "select de n negatif : EINVAL");

    tv = (struct timeval){ 0, -1 };
    errno = 0;
    r = brut_select(0, NULL, NULL, NULL, &tv);
    verifier(r == -1 && errno == EINVAL, "select, des microsecondes negatives : EINVAL");
    tv = (struct timeval){ -1, 1100000 };
    long long t0 = maintenant_ms();
    r = brut_select(0, NULL, NULL, NULL, &tv);
    long long duree = maintenant_ms() - t0;
    verifier(r == 0 && duree >= 100 && duree < 900 && tv.tv_sec == 0 && tv.tv_usec == 0,
             "select, {-1 s, 1 100 000 us} : 0,1 s (les microsecondes en trop comptent comme des secondes), le reste ecrit a zero");

    /* Au-delà de la table des descripteurs de Linux (64 cases, puis des
     * puissances de deux : un numéro 100 pris l'a fait passer à 128) : les
     * bits ne sont ni lus ni écrits. */
    dup2(pret, 100);
    close(100);
    uint64_t grand[32];
    memset(grand, 0, sizeof grand);
    grand[pret / 64] |= 1ull << (pret % 64);
    grand[200 / 64] |= 1ull << (200 % 64);
    grand[1500 / 64] |= 1ull << (1500 % 64);
    tv = (struct timeval){ 0, 0 };
    r = brut_select(2048, grand, NULL, NULL, &tv);
    verifier(r == 1 && grand[pret / 64] == 1ull << (pret % 64) && grand[200 / 64] == 1ull << (200 % 64)
             && grand[1500 / 64] == 1ull << (1500 % 64),
             "select au-dela de la table des descripteurs (128 cases) : ces bits ni lus ni ecrits");
    close(pret);
    close(vide);
    close(chemin);
}

/* L'événement que rend un epoll_wait sans attente (0 : aucun). */
static unsigned evs(int ep)
{
    struct epoll_event e[1];
    int n = epoll_wait(ep, e, 1, 0);
    return n == 1 ? e[0].events : n == 0 ? 0 : 0xdead;
}

static void ecrire(int fd, uint64_t v)
{
    if (write(fd, &v, 8) != 8)
        printf("[linux] attente : ecriture d'un eventfd : ECHEC\n");
}

static uint64_t lire(int fd)
{
    uint64_t v = 0;
    if (read(fd, &v, 8) != 8)
        return 0;
    return v;
}

static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

static void epolls(void)
{
    int ef = eventfd(0, EFD_NONBLOCK), ep = epoll_create1(0);
    struct epoll_event e = { .events = EPOLLIN | EPOLLET, .data.u32 = 1 };
    epoll_ctl(ep, EPOLL_CTL_ADD, ef, &e);
    ecrire(ef, 1);
    unsigned a = evs(ep), b = evs(ep);
    ecrire(ef, 1);
    unsigned c = evs(ep);
    verifier(a == EPOLLIN && b == 0 && c == EPOLLIN, "EPOLLET sur un eventfd : chaque ecriture redonne EPOLLIN, meme sans lecture entre deux");
    lire(ef);
    e.events = EPOLLIN;
    epoll_ctl(ep, EPOLL_CTL_MOD, ef, &e);
    ecrire(ef, 1);
    a = evs(ep);
    b = evs(ep);
    lire(ef);
    c = evs(ep);
    verifier(a == EPOLLIN && b == EPOLLIN && c == 0, "par niveau : EPOLLIN tant que le compteur n'est pas nul");
    e.events = EPOLLIN | EPOLLONESHOT;
    epoll_ctl(ep, EPOLL_CTL_MOD, ef, &e);
    ecrire(ef, 1);
    a = evs(ep);
    b = evs(ep);
    epoll_ctl(ep, EPOLL_CTL_MOD, ef, &e);
    c = evs(ep);
    verifier(a == EPOLLIN && b == 0 && c == EPOLLIN, "EPOLLONESHOT : une fois, puis rien jusqu'a un MOD");
    e.events = EPOLLOUT;
    epoll_ctl(ep, EPOLL_CTL_MOD, ef, &e);
    lire(ef);
    a = evs(ep);
    ecrire(ef, 0xfffffffffffffffeull);
    b = evs(ep);
    lire(ef);
    verifier(a == EPOLLOUT && b == 0, "EPOLLOUT d'un eventfd vide : pret ; plein : rien");

    /* Emboîtés : l'intérieur prêt rend l'extérieur prêt ; un prêt qui ne
     * l'est plus (le compteur lu) ne compte plus. */
    int ep2 = epoll_create1(0);
    struct epoll_event e2 = { .events = EPOLLIN, .data.u32 = 2 };
    epoll_ctl(ep2, EPOLL_CTL_ADD, ep, &e2);
    e.events = EPOLLIN;
    epoll_ctl(ep, EPOLL_CTL_MOD, ef, &e);
    a = evs(ep2);
    ecrire(ef, 1);
    b = evs(ep2);
    struct pollfd pf = { ep, -1, 0 };
    poll(&pf, 1, 0);
    short pret = pf.revents;
    lire(ef);
    pf.revents = 0;
    int n = poll(&pf, 1, 0);
    verifier(a == 0 && b == EPOLLIN && pret == (POLLIN | POLLRDNORM) && n == 0 && evs(ep2) == 0,
             "un epoll dans un epoll : l'interieur pret rend l'exterieur pret ; poll d'un epoll pret 0x41, vide de nouveau 0");

    /* close d'un numéro qu'un dup double : l'inscription reste ; au dernier
     * close, elle disparaît. */
    int d = dup(ef);
    close(ef);
    ecrire(d, 1);
    a = evs(ep);
    long r1 = erreur(epoll_ctl(ep, EPOLL_CTL_DEL, ef, &e));
    close(d);
    int ef2 = eventfd(1, 0);
    b = evs(ep);
    verifier(a == EPOLLIN && r1 == EBADF && b == 0,
             "close d'un numero qu'un dup double : l'inscription reste, DEL par l'ancien numero EBADF ; au dernier close, elle disparait");

    struct epoll_event t[2];
    long m0 = erreur(epoll_wait(ep, t, 0, 0)), mg = erreur(syscall(SYS_epoll_wait, ep, t, INT_MAX / 12 + 1, 0));
    long mf = erreur(syscall(SYS_epoll_wait, ep, (void *)8, 1, 0));
    epoll_ctl(ep, EPOLL_CTL_ADD, ef2, &e);
    long mf2 = erreur(syscall(SYS_epoll_wait, ep, (void *)8, 1, 0));
    long mk = erreur(syscall(SYS_epoll_wait, ep, (void *)0xffff800000000000ull, 1, 0));
    long mbad = erreur(epoll_wait(ef2, t, 1, 0));
    struct timespec ts = { 0, 1000000000 };
    long pw = erreur(syscall(SYS_epoll_pwait2, ep, t, 1, &ts, NULL, 8));
    sigset_t vide;
    sigemptyset(&vide);
    long pw2 = erreur(syscall(SYS_epoll_pwait, ep, t, 1, 0, &vide, 7));
    verifier(m0 == EINVAL && mg == EINVAL && mf == 0 && mf2 == EFAULT && mk == EFAULT && mbad == EINVAL && pw == EINVAL && pw2 == EINVAL,
             "epoll_wait : maxevents 0 ou trop grand EINVAL ; tampon a 8 : 0 sans evenement, EFAULT avec ; hors des programmes EFAULT ; pas un epoll EINVAL ; pwait2 1e9 ns, pwait masque de 7 : EINVAL");
    int ef3 = eventfd(0, 0);
    struct epoll_event ex = { .events = EPOLLIN | EPOLLRDNORM | EPOLLEXCLUSIVE };
    verifier(erreur(epoll_ctl(ep, EPOLL_CTL_ADD, ef3, &ex)) == EINVAL, "EPOLLEXCLUSIVE avec EPOLLRDNORM : EINVAL");
    close(ef3);
    close(ef2);
    close(ep);
    close(ep2);
}

/* epoll_wait sans délai, réveillé par un autre fil ; et un poll du même
 * eventfd, surveillé par un epoll en EPOLLEXCLUSIVE : une écriture réveille
 * les deux (l'entrée exclusive n'éteint pas l'ordinaire). */
static int ep_commun, ef_commun;
static volatile int reveils_ep, reveils_poll;

static void *attendre_epoll(void *rien)
{
    (void)rien;
    struct epoll_event e;
    if (epoll_wait(ep_commun, &e, 1, 3000) == 1)
        reveils_ep++;
    return NULL;
}

static void *attendre_poll(void *rien)
{
    (void)rien;
    struct pollfd q = { ef_commun, POLLIN, 0 };
    if (poll(&q, 1, 3000) == 1)
        reveils_poll++;
    return NULL;
}

/* Dix mille écritures en EPOLLET par un autre fil : chacune réveille
 * epoll_wait, aucune n'est perdue (un réveil perdu ferait attendre le
 * lecteur jusqu'à son délai de garde, 2 s, sans plus rien à venir). */
#define ECRITURES 10000
static volatile int ecrit;

static void *ecrire_dix_mille(void *rien)
{
    (void)rien;
    for (int i = 0; i < ECRITURES; i++) {
        ecrire(ef_commun, 1);
        ecrit = i + 1;
        if (i % 7 == 0)
            sched_yield();
    }
    return NULL;
}

/* Un fil ouvre, inscrit et ferme des eventfd prêts pendant que l'autre
 * attend : un événement rendu porte la donnée d'un eventfd encore ouvert au
 * début de l'attente (jamais celle d'un fermé avant : son élément a disparu
 * avec lui), et l'inscription d'un nouveau, sous un numéro et peut-être une
 * case qui servaient, réussit toujours. */
#define TOURS 300
static volatile int ferme_jusqu_a, fini_de_tourner, inscriptions_ratees;

static void *tourner(void *rien)
{
    (void)rien;
    for (int i = 1; i <= TOURS; i++) {
        int f = eventfd(1, 0);
        struct epoll_event e = { .events = EPOLLIN | EPOLLET, .data.u64 = (uint64_t)i };
        if (epoll_ctl(ep_commun, EPOLL_CTL_ADD, f, &e) != 0)
            inscriptions_ratees++;
        if (i % 3 == 0)
            sched_yield();
        close(f);
        __atomic_store_n(&ferme_jusqu_a, i, __ATOMIC_SEQ_CST);
    }
    fini_de_tourner = 1;
    return NULL;
}

static void attentes_epoll(void)
{
    pthread_t a, b;
    ep_commun = epoll_create1(0);
    ef_commun = eventfd(0, EFD_NONBLOCK);
    struct epoll_event e = { .events = EPOLLIN, .data.u32 = 7 };
    epoll_ctl(ep_commun, EPOLL_CTL_ADD, ef_commun, &e);
    cible_efd = ef_commun;
    lire_au_lieu_d_ecrire = 0;
    pthread_create(&a, NULL, ecrire_plus_tard, NULL);
    struct epoll_event r;
    long long t0 = maintenant_ms();
    int n = epoll_wait(ep_commun, &r, 1, -1);
    pthread_join(a, NULL);
    verifier(n == 1 && r.events == EPOLLIN && r.data.u32 == 7 && maintenant_ms() - t0 >= 50,
             "epoll_wait sans delai, un autre fil ecrit l'eventfd : reveille, la donnee rendue");
    lire(ef_commun);
    close(ep_commun);

    ep_commun = epoll_create1(0);
    e = (struct epoll_event){ .events = EPOLLIN | EPOLLEXCLUSIVE };
    epoll_ctl(ep_commun, EPOLL_CTL_ADD, ef_commun, &e);
    reveils_ep = reveils_poll = 0;
    pthread_create(&a, NULL, attendre_epoll, NULL);
    pthread_create(&b, NULL, attendre_poll, NULL);
    dormir_ms(50);
    ecrire(ef_commun, 1);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    verifier(reveils_ep == 1 && reveils_poll == 1, "un eventfd surveille en EPOLLEXCLUSIVE et par poll : une ecriture reveille les deux");
    lire(ef_commun);
    close(ep_commun);

    ep_commun = epoll_create1(0);
    e = (struct epoll_event){ .events = EPOLLIN | EPOLLET };
    epoll_ctl(ep_commun, EPOLL_CTL_ADD, ef_commun, &e);
    ecrit = 0;
    pthread_create(&a, NULL, ecrire_dix_mille, NULL);
    uint64_t total = 0;
    int perdu = 0;
    while (total < ECRITURES) {
        n = epoll_wait(ep_commun, &r, 1, 2000);
        if (n != 1) {
            perdu = 1;
            break;
        }
        total += lire(ef_commun);
    }
    pthread_join(a, NULL);
    verifier(!perdu && total == ECRITURES, "dix mille ecritures en EPOLLET d'un autre fil : aucun reveil perdu");
    close(ep_commun);

    ep_commun = epoll_create1(0);
    ferme_jusqu_a = fini_de_tourner = inscriptions_ratees = 0;
    pthread_create(&a, NULL, tourner, NULL);
    int perime = 0, recus = 0;
    while (!fini_de_tourner) {
        int avant = __atomic_load_n(&ferme_jusqu_a, __ATOMIC_SEQ_CST);
        struct epoll_event rs[8];
        n = epoll_wait(ep_commun, rs, 8, 20);
        for (int i = 0; i < n; i++) {
            recus++;
            if (rs[i].data.u64 <= (uint64_t)avant || rs[i].data.u64 > TOURS)
                perime = 1;
        }
    }
    pthread_join(a, NULL);
    verifier(!perime && inscriptions_ratees == 0 && evs(ep_commun) == 0,
             "un fil ouvre, inscrit et ferme des eventfd pendant l'attente : jamais l'evenement d'un ferme, aucune inscription refusee");
    close(ep_commun);
    close(ef_commun);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    sortes();
    reveils();
    masques();
    selects();
    epolls();
    attentes_epoll();
    printf("[linux] attente : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
