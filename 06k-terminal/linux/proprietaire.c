/*
 * Le propriétaire d'un fichier et les signaux d'entrée-sortie (6h), contre ce qu'en fait Linux 6.18
 * (mesuré) :
 *   - F_GETOWN, F_SETOWN et leurs versions _EX, F_GETOWNER_UIDS, F_GETSIG, F_SETSIG, et leurs refus ;
 *     FIOSETOWN et ses voisins, pour les sockets seulement ; `dup` partage, une fille n'hérite pas ;
 *   - SIGURG au propriétaire, à l'arrivée de l'octet urgent (TCP, AF_UNIX), sans O_ASYNC ; à un fil ;
 *   - O_ASYNC : ce qui le retient (socket, tube) ou non (un fichier ordinaire) ; SIGIO, et le signal
 *     de F_SETSIG, avec son si_code, son si_band et son si_fd ;
 *   - ce qui fait partir SIGIO : les données, le FIN, l'établissement, une connexion à accepter, la
 *     place qui revient après qu'on a vu qu'il n'y en avait plus ; pour un tube, l'autre bout.
 * Sur l'hôte comme chez nous.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS 17
#endif

static int echecs;

static void verifier(int ok, const char *quoi)
{
    /* La référence, c'est Linux 6.18 (et notre noyau) : sur l'hôte, ce programme tourne sous le
     * Linux de référence (.devcontainer/linux-de-reference.sh, dans la CI), et chaque différence
     * compte. */
    printf("[linux] proprietaire : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* Ce que le gestionnaire a vu, par signal. */
static volatile int vus[65];
static volatile int vu_code, vu_bande, vu_fd, vu_fil;
/* Les descripteurs des signaux 34 (F_SETSIG), dans l'ordre : ils se
 * mettent en file, un par événement. */
static volatile int fds_34[8], nombre_34;

static void gestionnaire(int sig, siginfo_t *i, void *c)
{
    (void)c;
    vus[sig]++;
    if (sig == 34 && nombre_34 < 8)
        fds_34[nombre_34++] = i->si_fd;
    vu_code = i->si_code;
    vu_bande = i->si_band;
    vu_fd = i->si_fd;
    vu_fil = syscall(SYS_gettid);
}

static void poser(int sig)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_sigaction = gestionnaire;
    a.sa_flags = SA_SIGINFO;
    sigaction(sig, &a, NULL);
}

static void attendre_ms(int ms)
{
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

/* Combien de `sig` sont arrivés depuis la dernière fois (le temps qu'ils arrivent). */
static int compte(int sig)
{
    attendre_ms(30);
    int n = vus[sig];
    vus[sig] = 0;
    return n;
}

static long brut(int fd, int commande, long argument)
{
    long r = syscall(SYS_fcntl, fd, commande, argument);
    return r;
}

static volatile int fin_du_fil;
static volatile int numero_du_fil;

static void *fil(void *p)
{
    (void)p;
    numero_du_fil = syscall(SYS_gettid);
    while (!fin_du_fil)
        attendre_ms(2);
    return NULL;
}

static void paire(struct sockaddr_in *x, int l, int *c, int *f)
{
    *c = socket(AF_INET, SOCK_STREAM, 0);
    connect(*c, (void *)x, sizeof *x);
    *f = accept(l, NULL, NULL);
}

static void commandes(void)
{
    int u[2], pid = getpid(), pg = getpgrp();
    verifier(pg > 0 && getpgid(0) == pg && getpgid(pid) == pg && getsid(0) > 0 && getpgid(999999) < 0 && errno == ESRCH, "getpgrp, getpgid, getsid");
    struct f_owner_ex e;
    unsigned uids[2] = { 9, 9 };
    socketpair(AF_UNIX, SOCK_STREAM, 0, u);
    int s = u[0];
    verifier(brut(s, F_GETOWN, 0) == 0, "F_GETOWN : 0 au depart");
    e.type = 7;
    e.pid = 7;
    verifier(fcntl(s, F_GETOWN_EX, &e) == 0 && e.type == F_OWNER_TID && e.pid == 0, "F_GETOWN_EX : F_OWNER_TID et 0 au depart");
    verifier(brut(s, F_GETOWNER_UIDS, (long)uids) == 0 && uids[0] == 0 && uids[1] == 0, "F_GETOWNER_UIDS : 0 et 0 au depart");
    verifier(brut(s, F_GETSIG, 0) == 0, "F_GETSIG : 0 au depart");
    verifier(fcntl(s, F_SETOWN, pid) == 0 && brut(s, F_GETOWN, 0) == pid, "F_SETOWN : le processus");
    verifier(brut(s, F_GETOWNER_UIDS, (long)uids) == 0 && uids[0] == getuid() && uids[1] == geteuid(), "F_GETOWNER_UIDS : qui l'a pose");
    verifier(fcntl(s, F_GETOWN_EX, &e) == 0 && e.type == F_OWNER_PID && e.pid == pid, "F_GETOWN_EX : F_OWNER_PID");
    /* (F_GETOWN brut d'un petit groupe ressemble à une erreur : c'est pour cela que la glibc passe
     * par F_GETOWN_EX.) */
    verifier(brut(s, F_SETOWN, -pg) == 0 && fcntl(s, F_GETOWN) == -pg, "F_SETOWN : un groupe, negatif");
    verifier(fcntl(s, F_GETOWN_EX, &e) == 0 && e.type == F_OWNER_PGRP && e.pid == pg, "F_GETOWN_EX : F_OWNER_PGRP");
    verifier(fcntl(s, F_SETOWN, 0) == 0 && brut(s, F_GETOWN, 0) == 0, "F_SETOWN 0 : plus personne");
    verifier(fcntl(s, F_GETOWN_EX, &e) == 0 && e.type == F_OWNER_PID && e.pid == 0, "F_SETOWN 0 : F_OWNER_PID et 0");
    verifier(fcntl(s, F_SETOWN, 999999) < 0 && errno == ESRCH, "F_SETOWN inconnu : ESRCH");
    verifier(fcntl(s, F_SETOWN, -999999) < 0 && errno == ESRCH, "F_SETOWN groupe inconnu : ESRCH");
    verifier(fcntl(s, F_SETOWN, (int)0x80000000) < 0 && errno == EINVAL, "F_SETOWN INT_MIN : EINVAL");
    verifier(brut(s, F_GETOWN, 0) == 0, "apres un refus : inchange");
    /* Un fil : par F_SETOWN, c'est un numéro de processus qui ne répond pas : 0 relu. */
    pthread_t t;
    pthread_create(&t, NULL, fil, NULL);
    while (!numero_du_fil)
        attendre_ms(1);
    verifier(fcntl(s, F_SETOWN, numero_du_fil) == 0 && brut(s, F_GETOWN, 0) == 0, "F_SETOWN d'un fil : accepte, 0 relu");
    e.type = F_OWNER_TID;
    e.pid = numero_du_fil;
    verifier(fcntl(s, F_SETOWN_EX, &e) == 0 && brut(s, F_GETOWN, 0) == numero_du_fil, "F_SETOWN_EX : un fil");
    e.type = 9;
    verifier(fcntl(s, F_GETOWN_EX, &e) == 0 && e.type == F_OWNER_TID && e.pid == numero_du_fil, "F_GETOWN_EX : F_OWNER_TID");
    e.type = F_OWNER_PGRP;
    e.pid = pg;
    verifier(fcntl(s, F_SETOWN_EX, &e) == 0 && fcntl(s, F_GETOWN) == -pg, "F_SETOWN_EX : un groupe");
    e.type = 9;
    e.pid = pid;
    verifier(fcntl(s, F_SETOWN_EX, &e) < 0 && errno == EINVAL, "F_SETOWN_EX, type 9 : EINVAL");
    e.type = F_OWNER_PID;
    e.pid = 999999;
    verifier(fcntl(s, F_SETOWN_EX, &e) < 0 && errno == ESRCH, "F_SETOWN_EX inconnu : ESRCH");
    e.type = F_OWNER_TID;
    e.pid = 0;
    verifier(fcntl(s, F_SETOWN_EX, &e) == 0 && brut(s, F_GETOWN, 0) == 0, "F_SETOWN_EX 0 : plus personne");
    verifier(fcntl(s, F_SETOWN_EX, (void *)8) < 0 && errno == EFAULT, "F_SETOWN_EX : EFAULT");
    verifier(fcntl(s, F_GETOWN_EX, (void *)8) < 0 && errno == EFAULT, "F_GETOWN_EX : EFAULT");
    verifier(brut(s, F_GETOWNER_UIDS, 8) < 0 && errno == EFAULT, "F_GETOWNER_UIDS : EFAULT");
    verifier(fcntl(s, F_SETSIG, 34) == 0 && brut(s, F_GETSIG, 0) == 34, "F_SETSIG 34");
    verifier(fcntl(s, F_SETSIG, 65) < 0 && errno == EINVAL, "F_SETSIG 65 : EINVAL");
    verifier(fcntl(s, F_SETSIG, -1) < 0 && errno == EINVAL, "F_SETSIG -1 : EINVAL");
    verifier(fcntl(s, F_SETSIG, 64) == 0 && brut(s, F_GETSIG, 0) == 64, "F_SETSIG 64");
    verifier(fcntl(s, F_SETSIG, 0) == 0 && brut(s, F_GETSIG, 0) == 0, "F_SETSIG 0");
    /* Les ioctl, sur une socket. */
    int v = pid;
    verifier(ioctl(s, FIOSETOWN, &v) == 0 && brut(s, F_GETOWN, 0) == pid, "FIOSETOWN");
    v = 7;
    verifier(ioctl(s, FIOGETOWN, &v) == 0 && v == pid, "FIOGETOWN");
    v = -pg;
    verifier(ioctl(s, SIOCSPGRP, &v) == 0 && fcntl(s, F_GETOWN) == -pg, "SIOCSPGRP");
    v = 7;
    verifier(ioctl(s, SIOCGPGRP, &v) == 0 && v == -pg, "SIOCGPGRP");
    v = 999999;
    verifier(ioctl(s, FIOSETOWN, &v) < 0 && errno == ESRCH, "FIOSETOWN inconnu : ESRCH");
    verifier(ioctl(s, FIOSETOWN, (void *)8) < 0 && errno == EFAULT, "FIOSETOWN : EFAULT");
    verifier(ioctl(s, FIOGETOWN, (void *)8) < 0 && errno == EFAULT, "FIOGETOWN : EFAULT");
    /* Partagé par dup. */
    fcntl(s, F_SETOWN, pid);
    int d = dup(s);
    verifier(brut(d, F_GETOWN, 0) == pid, "dup : le meme proprietaire");
    close(d);
    close(u[0]);
    close(u[1]);
    /* Un tube : fcntl, mais pas les ioctl. Un fichier ordinaire aussi ; O_PATH : non. */
    int q[2];
    if (pipe(q) < 0)
        verifier(0, "pipe");
    verifier(fcntl(q[0], F_SETOWN, pid) == 0 && brut(q[0], F_GETOWN, 0) == pid, "un tube : F_SETOWN");
    v = pid;
    verifier(ioctl(q[0], FIOSETOWN, &v) < 0 && errno == ENOTTY, "un tube : FIOSETOWN, ENOTTY");
    verifier(ioctl(q[0], SIOCSPGRP, &v) < 0 && errno == ENOTTY, "un tube : SIOCSPGRP, ENOTTY");
    int f = open("/etc/hosts", O_RDONLY);
    verifier(fcntl(f, F_SETOWN, pid) == 0 && brut(f, F_GETOWN, 0) == pid, "un fichier : F_SETOWN");
    verifier(fcntl(f, F_SETSIG, 34) == 0 && brut(f, F_GETSIG, 0) == 34, "un fichier : F_SETSIG");
    verifier(ioctl(f, FIOGETOWN, &v) < 0 && errno == ENOTTY, "un fichier : FIOGETOWN, ENOTTY");
    /* O_ASYNC : un fichier sans liste ne le retient pas. */
    verifier(fcntl(f, F_SETFL, O_ASYNC) == 0 && !(fcntl(f, F_GETFL) & O_ASYNC), "un fichier : O_ASYNC accepte, pas retenu");
    int oui = 1, non = 0;
    verifier(ioctl(f, FIOASYNC, &oui) < 0 && errno == ENOTTY, "un fichier : FIOASYNC 1, ENOTTY");
    verifier(ioctl(f, FIOASYNC, &non) == 0, "un fichier : FIOASYNC 0 : rien ne change");
    verifier(ioctl(f, FIOASYNC, (void *)8) < 0 && errno == EFAULT, "un fichier : FIOASYNC, EFAULT");
    close(f);
    verifier(fcntl(q[0], F_SETFL, O_ASYNC) == 0 && (fcntl(q[0], F_GETFL) & O_ASYNC), "un tube : O_ASYNC retenu");
    verifier(ioctl(q[0], FIOASYNC, &non) == 0 && !(fcntl(q[0], F_GETFL) & O_ASYNC), "un tube : FIOASYNC 0");
    verifier(ioctl(q[0], FIOASYNC, &oui) == 0 && (fcntl(q[0], F_GETFL) & O_ASYNC), "un tube : FIOASYNC 1");
    close(q[0]);
    close(q[1]);
    int o = open("/etc", O_PATH);
    verifier(fcntl(o, F_SETOWN, pid) < 0 && errno == EBADF, "O_PATH : F_SETOWN, EBADF");
    verifier(fcntl(o, F_GETOWN) < 0 && errno == EBADF, "O_PATH : F_GETOWN, EBADF");
    close(o);
}

static int lecteur_fd;

static void *lecteur(void *p)
{
    char o[8];
    (void)p;
    if (recv(lecteur_fd, o, 8, 0) <= 0)
        verifier(0, "le lecteur");
    return NULL;
}

static void urgent_tcp(void)
{
    int pid = getpid(), l = socket(AF_INET, SOCK_STREAM, 0), c, f;
    struct sockaddr_in x = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t n = sizeof x;
    char o[8];
    bind(l, (void *)&x, sizeof x);
    getsockname(l, (void *)&x, &n);
    listen(l, 8);
    paire(&x, l, &c, &f);
    send(c, "u", 1, MSG_OOB);
    verifier(compte(SIGURG) == 0, "TCP, urgent sans proprietaire : pas de SIGURG");
    recv(f, o, 1, MSG_OOB);
    fcntl(f, F_SETOWN, pid);
    send(c, "v", 1, MSG_OOB);
    verifier(compte(SIGURG) == 1 && vu_code == 128 && vu_bande == 0 && vu_fd == 0, "TCP, urgent : SIGURG, du noyau");
    recv(f, o, 1, MSG_OOB);
    send(c, "w", 1, MSG_OOB);
    attendre_ms(10);
    send(c, "x", 1, MSG_OOB);
    verifier(compte(SIGURG) == 2, "TCP, deux urgents : deux SIGURG");
    recv(f, o, 1, MSG_OOB);
    recv(f, o, 4, MSG_DONTWAIT);
    fcntl(f, F_SETOWN, -getpgrp());
    send(c, "y", 1, MSG_OOB);
    verifier(compte(SIGURG) == 1, "TCP, urgent : au groupe");
    recv(f, o, 1, MSG_OOB);
    struct f_owner_ex e = { F_OWNER_TID, numero_du_fil };
    fcntl(f, F_SETOWN_EX, &e);
    send(c, "z", 1, MSG_OOB);
    verifier(compte(SIGURG) == 1 && vu_fil == numero_du_fil, "TCP, urgent : a ce fil");
    recv(f, o, 1, MSG_OOB);
    /* F_SETSIG n'y change rien, sans O_ASYNC. */
    fcntl(f, F_SETOWN, pid);
    fcntl(f, F_SETSIG, 34);
    send(c, "a", 1, MSG_OOB);
    verifier(compte(SIGURG) == 1 && compte(34) == 0, "TCP, urgent, F_SETSIG sans O_ASYNC : SIGURG, rien d'autre");
    recv(f, o, 1, MSG_OOB);
    fcntl(f, F_SETSIG, 0);
    /* SO_OOBINLINE : il part aussi. */
    int oui = 1;
    setsockopt(f, SOL_SOCKET, SO_OOBINLINE, &oui, sizeof oui);
    send(c, "b", 1, MSG_OOB);
    verifier(compte(SIGURG) == 1, "TCP, urgent, SO_OOBINLINE : SIGURG");
    recv(f, o, 4, 0);
    oui = 0;
    setsockopt(f, SOL_SOCKET, SO_OOBINLINE, &oui, sizeof oui);
    close(c);
    close(f);
    /* La lecture s'arrête à la marque, et un signal y passe d'abord. Ici : SIGURG déjà livré. */
    /* O_ASYNC. */
    paire(&x, l, &c, &f);
    fcntl(f, F_SETOWN, pid);
    verifier(fcntl(f, F_SETFL, fcntl(f, F_GETFL) | O_ASYNC) == 0 && compte(SIGIO) == 0, "TCP, O_ASYNC : rien en le posant");
    verifier(fcntl(f, F_GETFL) & O_ASYNC, "TCP, O_ASYNC : retenu");
    send(c, "abc", 3, 0);
    verifier(compte(SIGIO) == 1 && vu_code == 128 && vu_bande == 0 && vu_fd == 0, "TCP, des donnees : SIGIO, du noyau");
    recv(f, o, 8, 0);
    verifier(compte(SIGIO) == 0, "TCP, une lecture : rien");
    fcntl(f, F_SETSIG, 34);
    send(c, "abc", 3, 0);
    verifier(compte(34) == 1 && compte(SIGIO) == 0, "TCP, F_SETSIG 34 : lui seul");
    verifier(vu_code == 1 && vu_bande == 0x41 && vu_fd == f, "TCP, F_SETSIG : POLL_IN, POLLIN|POLLRDNORM, le descripteur");
    recv(f, o, 8, 0);
    /* Un signal qui a ses propres codes : SI_SIGIO. SIGIO, lui, garde POLL_IN. */
    poser(SIGUSR1);
    fcntl(f, F_SETSIG, SIGIO);
    send(c, "a", 1, 0);
    verifier(compte(SIGIO) == 1 && vu_code == 1 && vu_fd == f, "TCP, F_SETSIG SIGIO : POLL_IN");
    recv(f, o, 8, 0);
    poser(SIGCHLD);
    fcntl(f, F_SETSIG, SIGCHLD);
    send(c, "a", 1, 0);
    verifier(compte(SIGCHLD) == 1 && vu_code == -5 && vu_fd == f, "TCP, F_SETSIG SIGCHLD : SI_SIGIO");
    recv(f, o, 8, 0);
    fcntl(f, F_SETSIG, 0);
    /* L'urgent, avec O_ASYNC. */
    send(c, "u", 1, MSG_OOB);
    verifier(compte(SIGURG) == 1 && compte(SIGIO) == 1, "TCP, urgent, O_ASYNC : SIGURG et SIGIO");
    recv(f, o, 1, MSG_OOB);
    fcntl(f, F_SETSIG, 34);
    send(c, "u", 1, MSG_OOB);
    int urg = compte(SIGURG), rt = compte(34);
    verifier(urg == 1 && rt == 3 && compte(SIGIO) == 0, "TCP, urgent, F_SETSIG 34 : SIGURG, et trois fois lui");
    recv(f, o, 1, MSG_OOB);
    fcntl(f, F_SETSIG, 0);
    /* Un lecteur qui attend : ce qui arrive est pour lui (SOCKWQ_ASYNC_WAITDATA). */
    lecteur_fd = f;
    pthread_t t;
    pthread_create(&t, NULL, lecteur, NULL);
    attendre_ms(30);
    send(c, "abc", 3, 0);
    pthread_join(t, NULL);
    verifier(compte(SIGIO) == 0, "TCP, un lecteur attend : pas de SIGIO");
    /* Le FIN : ce que dit `tcp_data_ready`, et ce que dit `tcp_fin`. */
    fcntl(f, F_SETSIG, 34);
    shutdown(c, SHUT_WR);
    verifier(compte(34) == 2 && vu_code == 1 && vu_bande == 0x41, "TCP, le FIN : POLL_IN, deux fois");
    close(c);
    verifier(compte(34) == 0, "TCP, close apres le FIN : rien");
    fcntl(f, F_SETSIG, 0);
    close(f);
    /* La place : seulement si on a vu qu'il n'y en avait plus. */
    paire(&x, l, &c, &f);
    fcntl(f, F_SETOWN, pid);
    fcntl(f, F_SETFL, fcntl(f, F_GETFL) | O_ASYNC | O_NONBLOCK);
    static char gros[65536];
    while (send(f, gros, sizeof gros, 0) > 0)
        ;
    verifier(compte(SIGIO) == 0, "TCP, plein : rien");
    fcntl(c, F_SETFL, O_NONBLOCK);
    while (recv(c, gros, sizeof gros, 0) > 0)
        attendre_ms(2);
    verifier(compte(SIGIO) >= 1, "TCP, la place revient : SIGIO");
    close(c);
    close(f);
    /* Le FIN de c chez f : deux POLL_IN (mesuré sous Linux, par F_SETSIG),
     * en un seul SIGIO s'ils arrivent ensemble, ou deux. Absorbés ici : ils
     * ne doivent pas compter dans la mesure suivante (6i : ils y comptaient,
     * et le test ne passait que si les signaux de la connexion se fondaient
     * aussi en un). */
    compte(SIGIO);
    /* Une connexion à accepter, et l'établissement : un signal de chacun.
     * Par un signal temps réel (F_SETSIG 34), qui se met en file avec son
     * descripteur : deux SIGIO ordinaires arrivés ensemble n'en font qu'un. */
    fcntl(l, F_SETOWN, pid);
    fcntl(l, F_SETSIG, 34);
    fcntl(l, F_SETFL, fcntl(l, F_GETFL) | O_ASYNC);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(s, F_SETOWN, pid);
    fcntl(s, F_SETSIG, 34);
    fcntl(s, F_SETFL, O_ASYNC | O_NONBLOCK);
    nombre_34 = 0;
    connect(s, (void *)&x, sizeof x);
    int n34 = compte(34);
    int l_vue = 0, s_vue = 0;
    for (int k = 0; k < nombre_34; k++) {
        l_vue += fds_34[k] == l;
        s_vue += fds_34[k] == s;
    }
    verifier(n34 == 2 && l_vue == 1 && s_vue == 1 && compte(SIGIO) == 0, "TCP, un connect : un signal a l'ecoute, un au client etabli");
    fcntl(l, F_SETSIG, 0);
    int a = accept(l, NULL, NULL);
    verifier(brut(a, F_GETOWN, 0) == 0 && !(fcntl(a, F_GETFL) & O_ASYNC), "TCP, une fille : ni proprietaire, ni O_ASYNC");
    /* Un RST : POLL_ERR. */
    fcntl(s, F_SETSIG, 34);
    struct linger g = { 1, 0 };
    setsockopt(a, SOL_SOCKET, SO_LINGER, &g, sizeof g);
    close(a);
    verifier(compte(34) >= 1 && vu_code == 4 && vu_bande == 8, "TCP, un RST : POLL_ERR, POLLERR");
    close(s);
    /* Fermée : plus de signal, quoi qu'il arrive à la connexion. */
    paire(&x, l, &c, &f);
    fcntl(f, F_SETOWN, pid);
    fcntl(f, F_SETFL, fcntl(f, F_GETFL) | O_ASYNC);
    compte(SIGIO);
    close(f);
    send(c, "u", 1, MSG_OOB);
    verifier(compte(SIGURG) == 0 && compte(SIGIO) == 0, "TCP, le fichier ferme : plus rien");
    close(c);
    close(l);
}

static void urgent_unix(void)
{
    int u[2], pid = getpid();
    char o[8];
    socketpair(AF_UNIX, SOCK_STREAM, 0, u);
    fcntl(u[1], F_SETOWN, pid);
    send(u[0], "ab", 2, MSG_OOB);
    verifier(compte(SIGURG) == 1 && vu_code == 128, "AF_UNIX, urgent : SIGURG");
    recv(u[1], o, 1, MSG_OOB);
    recv(u[1], o, 4, 0);
    fcntl(u[1], F_SETFL, fcntl(u[1], F_GETFL) | O_ASYNC);
    send(u[0], "ab", 2, 0);
    verifier(compte(SIGIO) == 1, "AF_UNIX, des donnees : SIGIO");
    recv(u[1], o, 4, 0);
    verifier(compte(SIGIO) == 0, "AF_UNIX, une lecture : rien");
    fcntl(u[0], F_SETOWN, pid);
    fcntl(u[0], F_SETFL, fcntl(u[0], F_GETFL) | O_ASYNC);
    send(u[1], "z", 1, 0);
    verifier(compte(SIGIO) == 1, "AF_UNIX, l'autre bout : SIGIO");
    recv(u[0], o, 4, 0);
    verifier(compte(SIGIO) == 0, "AF_UNIX, la place, sans l'avoir vue manquer : rien");
    fcntl(u[1], F_SETSIG, 34);
    shutdown(u[0], SHUT_WR);
    verifier(compte(34) == 1 && vu_code == 1 && vu_fd == u[1], "AF_UNIX, le FIN : POLL_IN");
    close(u[0]);
    verifier(compte(34) == 1 && vu_code == 6 && vu_bande == 0x18, "AF_UNIX, l'autre ferme : POLL_HUP");
    close(u[1]);
    /* Une écoute. */
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un { unsigned short f; char n[20]; } a = { AF_UNIX, "\0proprietaire" };
    bind(l, (void *)&a, 2 + 13);
    listen(l, 4);
    fcntl(l, F_SETOWN, pid);
    fcntl(l, F_SETFL, fcntl(l, F_GETFL) | O_ASYNC);
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (void *)&a, 2 + 13);
    verifier(compte(SIGIO) == 1, "AF_UNIX, une connexion a accepter : SIGIO");
    close(c);
    close(l);
    /* DGRAM. */
    socketpair(AF_UNIX, SOCK_DGRAM, 0, u);
    fcntl(u[1], F_SETOWN, pid);
    fcntl(u[1], F_SETFL, fcntl(u[1], F_GETFL) | O_ASYNC);
    send(u[0], "a", 1, 0);
    verifier(compte(SIGIO) == 1, "AF_UNIX, DGRAM : SIGIO");
    close(u[0]);
    close(u[1]);
}

static void udp(void)
{
    int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in y = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t n = sizeof y;
    bind(b, (void *)&y, sizeof y);
    getsockname(b, (void *)&y, &n);
    fcntl(b, F_SETOWN, getpid());
    fcntl(b, F_SETFL, fcntl(b, F_GETFL) | O_ASYNC);
    sendto(a, "a", 1, 0, (void *)&y, sizeof y);
    verifier(compte(SIGIO) == 1, "UDP : SIGIO");
    fcntl(b, F_SETFL, fcntl(b, F_GETFL) & ~O_ASYNC);
    sendto(a, "a", 1, 0, (void *)&y, sizeof y);
    verifier(compte(SIGIO) == 0, "UDP, O_ASYNC retire : rien");
    close(a);
    close(b);
}

static void tubes(void)
{
    int t[2], pid = getpid();
    char o[2];
    if (pipe(t) < 0)
        verifier(0, "pipe");
    /* O_ASYNC d'abord, le propriétaire ensuite : il sert dès qu'il est là. */
    fcntl(t[0], F_SETFL, fcntl(t[0], F_GETFL) | O_ASYNC);
    if (write(t[1], "a", 1) != 1)
        verifier(0, "ecrire");
    verifier(compte(SIGIO) == 0, "un tube, O_ASYNC sans proprietaire : rien");
    fcntl(t[0], F_SETOWN, pid);
    if (write(t[1], "a", 1) != 1)
        verifier(0, "ecrire");
    verifier(compte(SIGIO) == 1, "un tube, le lecteur : ce qui s'ecrit");
    if (read(t[0], o, 2) != 2)
        verifier(0, "lire");
    verifier(compte(SIGIO) == 0, "un tube, le lecteur : pas ce qui se lit");
    fcntl(t[1], F_SETOWN, pid);
    fcntl(t[1], F_SETFL, fcntl(t[1], F_GETFL) | O_ASYNC);
    fcntl(t[1], F_SETSIG, 34);
    if (write(t[1], "a", 1) != 1)
        verifier(0, "ecrire");
    verifier(compte(34) == 0 && compte(SIGIO) == 1, "un tube, l'ecrivain : pas ce qui s'ecrit");
    if (read(t[0], o, 1) != 1)
        verifier(0, "lire");
    verifier(compte(34) == 1 && vu_code == 2 && vu_bande == 0x304 && vu_fd == t[1], "un tube, l'ecrivain : ce qui se lit, POLL_OUT");
    fcntl(t[1], F_SETSIG, 0);
    fcntl(t[0], F_SETFL, fcntl(t[0], F_GETFL) & ~O_ASYNC);
    if (write(t[1], "a", 1) != 1)
        verifier(0, "ecrire");
    verifier(compte(SIGIO) == 0, "un tube, O_ASYNC retire : rien");
    if (read(t[0], o, 1) != 1)
        verifier(0, "lire");
    compte(SIGIO);
    /* Un lecteur inscrit voit la fermeture de l'autre bout (`pipe_release`). */
    fcntl(t[0], F_SETFL, fcntl(t[0], F_GETFL) | O_ASYNC);
    close(t[1]);
    verifier(compte(SIGIO) == 1, "un tube, l'ecrivain ferme : SIGIO");
    close(t[0]);
    /* Et l'autre sens. */
    if (pipe(t) < 0)
        verifier(0, "pipe");
    fcntl(t[1], F_SETOWN, pid);
    fcntl(t[1], F_SETFL, fcntl(t[1], F_GETFL) | O_ASYNC);
    close(t[0]);
    verifier(compte(SIGIO) == 1, "un tube, le lecteur ferme : SIGIO");
    close(t[1]);
}

int main(void)
{
    poser(SIGURG);
    poser(SIGIO);
    poser(34);
    commandes();
    urgent_tcp();
    urgent_unix();
    udp();
    tubes();
    fin_du_fil = 1;
    printf("[linux] proprietaire : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
